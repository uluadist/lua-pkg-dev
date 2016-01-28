local pkgu    = require 'pkg'.util
local xsys    = require 'xsys'
local lfs     = require 'lfs'
local serpent = require 'serpent'
local time    = require 'time'
local md5     = require 'md5'

-- TODO: Remove dependency on xsys.
local trim, split = xsys.string.trim, xsys.string.split
local append = xsys.table.append
local jos, jarch = jit.os, jit.arch

-- TODO: Aggregate multiple luarocks into same package to solve some conflicts.
-- TODO: Implement external libraries handling.
-- TODO: Implement proper semantic versioning.
-- TODO: Refactor: 
-- TODO: + rock.name, rock.version.
-- TODO: + pass around save_error, save_error_sys, save_pass.
-- TODO: Are all these utilities useful in general (xsys? use pl instead?) ?

-- Create a valid path name:
local function D(...)
  return table.concat({ ... }, '/')
end

local function mkdir_all(p)
  local sp = split(p, '/')
  for i=1,#sp-1 do
    local pp = table.concat(sp, '/', 1, i)
    lfs.mkdir(pp)
  end
end

local function pathfilesattr(p, o)
  o = o or { }
  for f in lfs.dir(p) do
    if f ~= "." and f ~= ".." then
      local pf = p..'/'..f
      local pfmode = lfs.attributes(pf).mode
      if pfmode == 'directory' then
        pathfilesattr(pf, o)
      elseif pfmode == 'file' then
        o[pf] = lfs.attributes(pf)
      else
        error('unexpected path mode "'..pfmode..'"')
      end
    end
  end
  return o
end

-- Files only (ignore empty folders).
local function pathdiff(p0attr, p1attr)
  local rem, add, mod = { }, { }, { }
  for f,_ in pairs(p0attr) do
    if not p1attr[f] then
      rem[#rem + 1] = f
    end
  end
  for f,_ in pairs(p1attr) do
    if not p0attr[f] then
      add[#add + 1] = f
    elseif p0attr[f].modification ~= p1attr[f].modification then
      mod[#mod + 1] = f
    end
  end
  local new = append(add, mod)
  table.sort(rem); table.sort(add); table.sort(mod); table.sort(new)
  return new, rem, add, mod
end

local function file_exist(filename)
  local f = io.open(filename)
  if f then
    f:close()
  end
  return f ~= nil
end

local function file_read(filename, opt)
  opt = opt or 'rb'
  local f = assert(io.open(filename, opt))
  local s = f:read('*a')
  assert(f:close())
  return s
end

local function file_write(filename, s)
  local f = assert(io.open(filename, 'wb'))
  f:write(s)
  assert(f:close())
end

local function load_config(s)
  local env = { }
  local f = assert(loadstring(s))
  setfenv(f, env)
  f()
  return env
end

local function deserialize(s)
  return assert(loadstring(s))()
end

local function serialize(t)
  return 'return '..serpent.block(t, { comment = false })
end

-- TODO: Add example file.
local config_filename = D(os.getenv('LUA_ROOT'), 'host', 'config-dev.lua')
local config = deserialize(file_read(config_filename))
local luarocks_address = config.luarocks_address
local dir              = config.dir
local cmd              = config.cmd
local show_new_only    = config.show_new_only

local function execute(command, fstdout, fstderr)
  local toexecute = command..' > '..fstdout..' 2> '..fstderr
  return os.execute(toexecute)
end

local function to_unix_eol(paths)
  for i=1,#paths do
    local command = cmd.dos2unix..' '..paths[i]
    assert(execute(command, dir.null, dir.null) == 0)
  end
end

--------------------------------------------------------------------------------
local function copy_table(t)
  if type(t) ~= 'table' then
    return t
  end
  local o = { }
  for k, v in pairs(t) do
    o[k] = copy_table(v) 
  end
  return o
end

local function keys_to_array(t)
  local o = { }
  for k in pairs(t) do 
    o[#o + 1] = k 
  end
  return o
end

local function array_to_true(x)
  local o = { }
  for i=1,#x do
    o[x[i]] = true
  end
  return o
end

local function setvarg(t, v, k, ...)
  local nextk = ...
  if not nextk then
    t[k] = v
  else
    t[k] = type(t[k]) ~= 'nil' and t[k] or { }
    setvarg(t[k], v, ...)
  end
end

local function getvarg(t, k, ...)
  local nextk = ...
  if not nextk then
    return t[k]
  elseif type(t[k]) == 'nil' then
    return nil
  else
    return getvarg(t[k], ...)
  end
end

--------------------------------------------------------------------------------
local write_persisted = { }

local function persistent(filename)
  local serialized = file_exist(filename) and deserialize(file_read(filename))
  local persisted = serialized or { }
  write_persisted[persisted] = function()
    serialized = serialize(persisted)
    file_write(filename, serialized)
  end
  return persisted
end

-- rockname -> upkgversion -> os -> arch -> true/false:
local rock_pass        = persistent(D(dir.luarocks_state, 'pass.lua'))

-- rockname -> rockversion -> modules -> true:
local rock_modules     = persistent(D(dir.luarocks_state, 'modules.lua'))

-- TODO
local module_bundles   = persistent(D(dir.luarocks_state, 'bundles.lua'))

-- excludeid -> rockname -> rockversion -> { rock_ name, rock_ version }:
local rock_exclude_sys = persistent(D(dir.luarocks_state_sys, 
  'exclude_sys.lua'))

-- errorid -> rockname -> rockversion -> errormessage:
local rock_error       = persistent(D(dir.luarocks_state, 'error.lua'))
-- errorid -> rockname -> rockversion -> errormessage:
local rock_error_sys   = persistent(D(dir.luarocks_state_sys, 'error_sys.lua'))

local function notnil(x)
  return type(x) ~= 'nil'
end

local function logger(kind, name, version)
  assert(kind and name and version)
  return function(message, ...)
    assert(notnil(message))
    setvarg(kind, message, name, version, ...)
    write_persisted[kind]()
  end
end

local function id_logger(kind, name, version)
  assert(kind and name and version)
  return function(id, message, ...)
    assert(notnil(id) and notnil(message))
    setvarg(kind, message, id, name, version, ...)
    write_persisted[kind]()
  end
end

local function has_error(kind, targetrockname, targetrockversion)
  for id,rocknames in pairs(kind) do
    for rockname,rockversions in pairs(rocknames) do
      for rockversion,info in pairs(rockversions) do
        if rockname == targetrockname and (rockversion == targetrockversion or rockversion..'-0' == targetrockversion) then 
          return id, info
        end
      end
    end     
  end
end

local function module_exist(kind, targetmodulename)
  for rockname,rockversions in pairs(kind) do
    for rockversion,modules in pairs(rockversions) do
      for modulename in pairs(modules) do
        -- Case insensitive as some OS are so:
        if modulename:lower() == targetmodulename:lower() then 
          return rockname, rockversion
        end
      end
    end
  end     
end

--------------------------------------------------------------------------------
local function is_valid_version(version)
  local ok = pcall(pkgu.versplit, version)
  if not ok then
    return nil, version..' is not a valid module version'
  end
  return true
end

-- Rock and upkg versions only differ in the release number.

-- TODO: Change
local PKG_VER = 3
local PKG_MUL = 100

assert(PKG_VER <= PKG_MUL - 1)

local function upkg_release(rockname, pre_release, release)
  release = release and assert(tonumber(release)) or 0
  assert(release >= 0, release)
  return tostring(release*PKG_MUL + PKG_VER)
end

local function rock_release(rockname, pre_release, release)
  release = assert(tonumber(release))
  assert(release >= 0, release)
  return tostring(math.floor(release/PKG_MUL))
end

local function to_upkg_version(rockname, rockversion)
  local pre_release, release = unpack(split(rockversion, '-'))
  return pre_release..'-'..upkg_release(rockname, pre_release, release)
end

local function to_rock_version(rockname, upkgversion)
  local pre_release, release = unpack(split(upkgversion, '-'))
  return pre_release..'-'..rock_release(rockname, pre_release, release)
end

--------------------------------------------------------------------------------
local function download_rockspec(rockname, rockversion)
  local rockspec_filename = rockname..'-'..rockversion..'.rockspec'
  local rockspec_path = D(dir.luarocks_repository, 'spec', rockspec_filename)  
  if not file_exist(rockspec_path) then
    local ok, rockspec_code = pcall(pkgu.download, luarocks_address, 
      rockspec_filename)
    if not ok then
      return nil, rockspec_code
    end
    file_write(rockspec_path, rockspec_code)
  end
  return true
end

local function load_downloaded_rockspec(rockname, rockversion)
  local rockspec_filename = rockname..'-'..rockversion..'.rockspec'
  local rockspec_path = D(dir.luarocks_repository, 'spec', rockspec_filename)
  local rockspec_code = file_read(rockspec_path)
  local ok, rockspec = pcall(load_config, rockspec_code)
  if not ok then
    return nil, rockspec
  end
  return rockspec
end

local function is_lua_dependency(s)
  return s:find('^lua ') or s == 'lua'
end

-- TODO: Use Luarocks version-parser.
local function get_unsupported_lua(v)
  if v:find('lua >= 5.2') 
  or v:find('lua >= 5.3')
  or v:find('lua ~> 5.2') 
  or v:find('lua ~> 5.3')
  or v:find('lua == 5.2') 
  or v:find('lua == 5.3')
  or v:find('lua > 5.1') then
    return v
  end
end

local function is_supported_lua(rockspec)
  local unsupported_lua = false
  for _,dependency in ipairs(rockspec.dependencies or { }) do
    if is_lua_dependency(dependency) then
      unsupported_lua = unsupported_lua or get_unsupported_lua(dependency)
    end
  end
  if unsupported_lua then
    return nil, unsupported_lua
  end
  return true
end

local luarocksos_to_luaos = {
  ['!windows'] = 'Linux,OSX',
  windows      = 'Windows',
  win32        = 'Windows',
  macosx       = 'OSX',
  linux        = 'Linux',
  unix         = 'OSX,Linux',
  bsd          = 'OSX',
}

local function is_supported_os(rockspec)
  if not rockspec.supported_platforms then
    return true
  end
  local supported_os = false
  for _,os in ipairs(rockspec.supported_platforms) do
    supported_os = supported_os or (luarocksos_to_luaos[os] or ''):find(jos)
  end
  if not supported_os then
    return nil, rockspec.supported_platforms
  end
  return true
end

local function is_supported_external_libraries(rockspec)
  if rockspec.external_dependencies then
    return nil, rockspec.external_dependencies
  end
  return true
end

-- TODO: Use Luarocks version-parser.
local function name_version_dependency(s)
  local first = unpack(split(s, ','))
  -- We consider all the below equal and impose semantic versioning:
  first = first:gsub(' ~> ', ' >= ')
               :gsub(' ~= ', ' >= ')
               :gsub(' == ', ' >= ')
               :gsub(' > ',  ' >= ')
               :gsub(' = ',  ' >= ')
  -- Deal with unsupported but valid spec:
  first = first:gsub('lua < 5.3', 'lua >= 5.1')
  -- Deal with badly formatted dependencies, just a space between name and ver:
  if not first:find('>=') then
    first = first:gsub(' ', '>=')
  end
  local name, version = unpack(split(first, '>='))
  name = trim(name)
  if version then
    version = trim(version)
    local ok, err = is_valid_version(version)
    if not ok then
      return nil, err
    end
    return name, version
  else
    return name
  end
end

local function is_valid_version_dependencies(rockspec)
  for _,dependency in ipairs(rockspec.dependencies or { }) do
    if not name_version_dependency(dependency) then
      return nil, dependency
    end
  end
  return true
end

local function upkg_dependencies(rockspec, all_valid_versions)
  local out = { luajit = '2.0' }
  for _,dependency in ipairs(rockspec.dependencies or { }) do
    if not is_lua_dependency(dependency) then
      local name, version = name_version_dependency(dependency)
      if not version then
        local info = pkgu.infobest(all_valid_versions, name)
        if info then
          version = info.version
        else
          -- False is not a valid version string format of course, but it will 
          -- result in correct logic when trying to install dependencies, i.e. 
          -- 'dependency_unavailable' in install():
          version = false
        end
      end
      out[name] = version
    end
  end
  return out
end

local function upkg_repo_all_valid_versions(manifest_repository)
  local all_valid_versions = { }
  for rockname,rockversions in pairs(manifest_repository) do
    for rockversion,_ in pairs(rockversions) do
      if is_valid_version(rockversion) then
        pkgu.infoinsert(all_valid_versions, rockname, { 
          version = rockversion
        })
      end
    end
  end
  return all_valid_versions
end

local function description_field(description, field, rockname)
  local desc
  if description and description[field] then
    desc = description[field]
  else
    desc = ''
  end
  if rockname then
    return rockname..' : '..desc
  else
    return desc
  end
end

local function save_pass(rockname, rockversion, status)
  local upkgversion = to_upkg_version(rockname, rockversion)
  local save = logger(rock_pass, rockname, upkgversion)
  save(status, jos, jarch)
  return status
end

local function upkg_repo_valid(manifest_repository)
  local all_valid_versions = upkg_repo_all_valid_versions(manifest_repository)
  local valid = { }
  for rockname,rockversions in pairs(manifest_repository) do
    for rockversion,_ in pairs(rockversions) do
      local save_error     = id_logger(rock_error,     rockname, rockversion)
      local save_error_sys = id_logger(rock_error_sys, rockname, rockversion)

      local ok = is_valid_version(rockversion)
      if not ok then
        save_error('not_valid_version_format', rockversion) 
        save_pass(rockname, rockversion, false)
        break 
      end

      local err
      ok, err =  download_rockspec(rockname, rockversion)
      if not ok then
         save_error('rock_download_error', err) 
         save_pass(rockname, rockversion, false)
         break
      end

      ok, err = load_downloaded_rockspec(rockname, rockversion)
      if not ok then
        save_error('rock_loadstring_error', err) 
        save_pass(rockname, rockversion, false)
        break
      end
      local rockspec = ok

      ok, err = is_supported_os(rockspec)
      if not ok then
        save_error_sys('unsupported_os', err) 
        save_pass(rockname, rockversion, false)
        break
      end

      ok, err = is_supported_external_libraries(rockspec)
      if not ok then
        save_error('unsupported_external_library', err) 
        save_pass(rockname, rockversion, false)
        break
      end

      ok, err = is_supported_lua(rockspec)
      if not ok then
        save_error('unsupported_lua_version', err) 
        save_pass(rockname, rockversion, false)
        break
      end

      ok, err = is_valid_version_dependencies(rockspec)
      if not ok then
        save_error('not_valid_version_format_of_dependency', err)
        save_pass(rockname, rockversion, false)
        break
      end

      local dependencies = upkg_dependencies(rockspec, all_valid_versions)

      local description = rockspec.description
      -- To get actual __meta.lua it is still necessary to modify 'require' to 
      -- account for rockname -> { modules } and to add intra-dependencies 
      -- (same reason); it is also necessary to set a version to the upkgversion
      -- , to remove rockspec and to add name.
      local info = {
        version     = rockversion,
        require     = dependencies,
        -- These are not going to be modified:
        description = description_field(description, 'summary',  rockname),
        license     = description_field(description, 'license'),
        homepage    = description_field(description, 'homepage'),
      }
      pkgu.infoinsert(valid, rockname, info)
    end
  end
  return valid
end

local function init_manifest()
  local manifest_path = D(dir.luarocks_repository, 'manifest.lua')
  local manifest_code = file_read(manifest_path) -- Saved without byte opt.
  local manifest = load_config(manifest_code)
  return manifest
end

local function repo_from_manifest()
  local manifest = init_manifest()
  return upkg_repo_valid(manifest.repository)
end

--------------------------------------------------------------------------------
local function is_in_boundle(modules, rockname)
  local amodules = keys_to_array(modules)
  local name = amodules[1]
  if #amodules == 1 and module_bundles[name] then
    for _,p in ipairs(module_bundles[name].pattern) do
      if rockname:find(p) then
        print('BUNDLE', rockname, name)
        return true
      end
    end
  end
  return false
end

local function bundle_hash(metas)
  local hash = { }
  for _,m in ipairs(metas) do
    hash[#hash + 1] = m.name
    hash[#hash + 1] = m.version
  end
  return md5.sumhexa(table.concat(hash))
end

local function bundle_require(metas)
  local require = { }
  for _,m in ipairs(metas) do
    for name,version in pairs(m.require) do
      if require[name] then
        assert(require[name] == version) -- Simplistic approach.
      else
        require[name] = version
      end
    end
  end
  return require
end

local function bundle_license(metas)
  local license = { }
  for _,m in ipairs(metas) do
    license[m.license] = true
  end
  return table.concat(keys_to_array(license), ' + ')
end

local function bundle_description(metas, bundlename)
  local description = { }
  for _,m in ipairs(metas) do
    description[#description + 1] = m.name..'~'..m.version..': '..m.description
  end
  return bundlename..'-bundle: '..table.concat(description, ' + ')
end

local function bundle_copy_parhs(metas)

end

--------------------------------------------------------------------------------
local function install_rock(rockname, rockversion)
  local luarockscmd = cmd.luarocks..'install '..rockname..' '..rockversion
  local logpath = D(dir.luarocks_state_sys, 'log', rockname..'~'..rockversion)
  local logstdout = logpath..'_out.txt'
  local logstderr = logpath..'_err.txt' 
  local errorcode = execute(luarockscmd, logstdout, logstderr)
  if errorcode ~= 0 then -- TODO: Check ok to do binary in windows for this.
    local msg = { 
      stdout = rockname..'~'..rockversion..'_out.txt', 
      stderr = rockname..'~'..rockversion..'_err.txt', 
    }
    local save_error_sys = id_logger(rock_error_sys, rockname, rockversion)
    save_error_sys('luarocks_install_error', msg)
    return nil, file_read(logstderr)
  end
  return true
end

local function changed_paths(directory, f, ...)
  local dir_before = pathfilesattr(directory)
  local ok, err = f(...)
  if not ok then
    return nil, err
  end
  local dir_after = pathfilesattr(directory)
  return (pathdiff(dir_before, dir_after))
end

------------
local function content_if_find(path, tomatch)
  local _, last = path:find(tomatch, 1, true) -- Plain matching.
  return last and path:sub(last + 2)
end

local function discard_2_args(_, _, ...)
  return ...
end

local function captures(s, pattern)
  return discard_2_args(s:find(pattern))
end

local function match_modulenames_content_lua(path)
  local content = content_if_find(path, dir.luarockstree_lua)
  if content then
    local plain_modulename = captures(content, '^([^/]+)%.lua')
    if plain_modulename then
      return true, { plain_modulename }, 'init.lua'
    end
    local modulename, lua_content = captures(content, '^([^/]+)/(.+)')
    if modulename and lua_content then
      return true, { modulename }, lua_content
    end
    -- Plain files not ending in '.lua' in dir.luarockstree_lua are skipped:
    return true
  end
end

-- TODO: OSX: .dylib or .so?
local os_clib_extension = {
  Windows = 'dll',
  Linux   = 'so',
  OSX     = 'so',
}
local clib_extension = os_clib_extension[jos]

local function match_modulenames_content_clua(path)
  local content = content_if_find(path, dir.luarockstree_clua)
  if content then
    assert(content:find('%.'..clib_extension), content)
    local clua_content = D(jos, jarch, '-'..content:gsub('/', '_'))
    local plain_modulename = captures(content, '^([^/]+)%.'..clib_extension)
    if plain_modulename then
      return true, { plain_modulename }, clua_content
    end
    local modulename = captures(content, '^([^/]+)')
    return true, { modulename }, clua_content
  end
end

local function match_modulenames_content_extra(path, rockname, rockversion, 
  modules)
  local tomatch = D(dir.luarockstree_extra, rockname, rockversion)
  local content = content_if_find(path, tomatch)
  if content then
    local rockspec = rockname..'-'..rockversion..'.rockspec'
    if content ~= 'rock_manifest' and content ~= rockspec then
      if content:find('^bin') then -- Handle executable scripts case.
        local script_content = file_read(path)
        local script_parse_ok = loadstring(script_content)
        if not script_parse_ok then
          return true -- Not valid Lua scripts are skipped.
        end
      end
      content = content and '__'..content
      -- TODO: Use sys_rock_error here.
      assert(content ~= '__meta.lua') -- Reserved for package manager.
      local modulenames = keys_to_array(modules)
      -- If no lua or clua files have been installed modules will be an empty
      -- table (this can happen for pure-script luarocks for instance; this is 
      -- not desiderable as the extra files would be lost, hence use rockname:
      if #modulenames == 0 then
        modulenames[1] = rockname
      end
      return true, modulenames, content
    end
    return true
  end
end

local function fixed_width(s, nchar)
  return s:sub(1, math.min(#s, nchar))..(' '):rep(math.max(nchar - #s, 0))
end

local function remove_expected(unmatched)
  unmatched[D(dir.luarockstree_extra, 'manifest')] = nil
  for file in pairs(unmatched) do
    if file:find(dir.luarockstree_bin, 1, true) then
      unmatched[file] = nil
    end
  end
end

local function has_module_conflict(modules, rockname, rockversion)
  if not is_in_boundle(modules, rockname) then
    for modulename in pairs(modules) do
      local in_rockname, in_rockversion = module_exist(rock_modules, modulename)
      if in_rockname and in_rockname ~= rockname then
        local save_error = id_logger(rock_error, rockname, rockversion)
        save_error('module_conflict', { 
          module_name = modulename,
          rock_name = in_rockname, 
          rock_version = in_rockversion 
        })
        return modulename
      end
    end
  end
  return false
end

local function module_dir_upkg(rockname, upkgversion, modulename)
  assert(rockname and upkgversion and modulename)
  return D(dir.luarocks_package, rockname, upkgversion, modulename)
end

local function module_dir(rockname, rockversion, modulename)
  return module_dir_upkg(rockname, to_upkg_version(rockname, rockversion), 
    modulename)
end

local function handle(modules, unmatched, installed_paths, handler, 
  rockname, rockversion)
  for _, path in ipairs(installed_paths) do
    local match, modulenames, content = handler(path, rockname, rockversion, 
      modules)
    if match then
      assert(unmatched[path]) -- Multiple match is matching logic error!
      unmatched[path] = nil
    end
    if content then
      for _, modulename in ipairs(modulenames) do
        local to = D(module_dir(rockname, rockversion, modulename), content) 
        modules[modulename] = modules[modulename] or { }
        if modules[modulename][to] then
          local save_error_sys = id_logger(rock_error_sys, rockname, 
            rockversion)
          save_error_sys('destination_already_set', to)
          return nil, 'destination already set '..to
        end
        modules[modulename][to] = path
      end
    end
  end
  return true
end

local function modules_links(installed_paths, rockname, rockversion)
  local modules, unmatched = { }, array_to_true(installed_paths)

  local lua_ok, lua_err = handle(modules, unmatched, installed_paths, 
    match_modulenames_content_lua, rockname, rockversion)
  if not lua_ok then
    return nil, lua_err
  end

  local clua_ok, clua_err = handle(modules, unmatched, installed_paths, 
    match_modulenames_content_clua, rockname, rockversion)
  if not clua_ok then
    return nil, clua_err
  end

  local extra_ok, extra_err = handle(modules, unmatched, installed_paths, 
    match_modulenames_content_extra, rockname, rockversion)
  if not extra_ok then
    return nil, extra_err
  end

  remove_expected(unmatched)
  local unmatched_array = keys_to_array(unmatched)
  if #unmatched_array > 0 then
    local save_error_sys = id_logger(rock_error_sys, rockname, rockversion)
    save_error_sys('unexpected_files', unmatched_array)
    local unmatched_text = table.concat(unmatched_array, '\n')
    return nil, 'unexpected files: '..unmatched_text
  end
  return modules
end

local function copy_links(links, rockname, rockversion)
  for to, from in pairs(links) do
    local content = file_read(from)
    if file_exist(to) then
      local existing_content = file_read(to)
      if existing_content ~= content then
        local save_error = id_logger(rock_error, rockname, rockversion)
        save_error('file_os_conflict', {
          from = from,
          to = to,
          current_os = jos,
        })
        return nil, 'file os conflict: '..to
      end
    else
      mkdir_all(to)
      file_write(to, content)
    end
  end
  return true
end

local function copy_modules_links(modules, rockname, rockversion)
  for _, links in pairs(modules) do
    local ok, err = copy_links(links, rockname, rockversion)
    if not ok then
      return nil, err
    end
  end
  return true
end

local function copy_modules_meta(meta, rockname, rockversion)
  for modulename, modulemeta in pairs(meta) do
    local content = serialize(modulemeta)
    local to = D(module_dir(rockname, rockversion, modulename), '__meta.lua')
    if file_exist(to) then
      local existing_content = file_read(to)
      if existing_content ~= content then
        error(existing_content..' ~= '..content)
      end
    else
      file_write(to, content)
    end
  end
end

local function fix_require_rocknames_to_modules(modulemeta, repo)
  local fixed_require = { }
  for dep_name, dep_version in pairs(modulemeta.require) do
    if dep_name ~= 'luajit' and dep_name ~= 'pkg' then
      local info = assert(pkgu.infobest(repo, dep_name, dep_version))
      local target_version = info.version
      local modules = assert(getvarg(rock_modules, dep_name, target_version))
      for dep_modulename in pairs(modules) do
        if dep_modulename ~= modulemeta.name then -- No bundle self-dependency.
          fixed_require[dep_modulename] = dep_version
        end
      end
    else
      fixed_require[dep_name] = dep_version
    end
  end
  modulemeta.require = fixed_require
end

local function add_intra_dependencies(modulename, modulemeta, meta, upkgversion)
  for othermodulename in pairs(meta) do
    if modulename ~= othermodulename then
      modulemeta.require[othermodulename] = upkgversion
    end
  end
end

local function get_meta(info, modules, rockname, rockversion, repo)
  local upkgversion = to_upkg_version(rockname, rockversion)
  local meta_common = { 
    version     = upkgversion, -- Info.version is rockversion.
    require     = info.require,
    description = info.description, 
    license     = info.license,
    homepage    = info.homepage,
  }
  local meta = { }
  for modulename in pairs(modules) do
    meta[modulename] = copy_table(meta_common)
    meta[modulename].name = modulename
    fix_require_rocknames_to_modules(meta[modulename], repo)
  end
  for modulename, modulemeta in pairs(meta) do
    add_intra_dependencies(modulename, modulemeta, meta, upkgversion)
  end
  return meta
end

local function check_has_files(paths, rockname, rockversion)
  if #paths == 0 then
    local save_error_sys = id_logger(rock_error_sys, rockname, rockversion)
    save_error_sys('no_installed_files', true)
    return nil
  end
  return true
end

local function status_printer(rockname, rockversion, level)
  assert(rockname and rockversion)
  return function(status, message, exclude)
    assert(status)
    if not exclude then
      local fixed_status = fixed_width((' '):rep(level)..status, 10)
      local fixed_name_version = fixed_width(rockname..'~'..rockversion, 32)
      io.write(fixed_status, ' : ', fixed_name_version)
      if message then
        io.write(' : ', message)
      end
      io.write('\n')
    end
  end
end

local function install(repo, rockname, rockversion, level)
  level = level or 0
  local print_status = status_printer(rockname, rockversion or '<latest>', 
    level)

  local als_install_unstable = not rockversion

  local vinfo = repo[rockname]
  if not vinfo then
    print_status('FAIL', 'unavailable rock', show_new_only) 
    return nil
  end

  local info = pkgu.infobest(repo, rockname, rockversion)
  if not info then
    print_status('FAIL', 'unavailable rock version', show_new_only)
    return nil
  end

  rockversion = rockversion or info.version
  print_status = status_printer(rockname, rockversion,  level)

  -- Has to be before rock_pass check because subsequent OS-specific build
  -- can set an error in rock_error due to filename differences.
  if has_error(rock_error,     rockname, rockversion) or
     has_error(rock_error_sys, rockname, rockversion) then
     print_status('FAIL', 'previous failure', show_new_only)
     -- Necessary to update this as runs on other OS might have set failure 
     -- in rock_error:
     return save_pass(rockname, rockversion, false)
     -- Notice that some OS will not be true nor false as unsupported OS 
     -- rocks installs are not even attampted (repo exclusion).
  end

  local upkversion = to_upkg_version(rockname, rockversion)
  if getvarg(rock_pass, rockname, upkversion, jos, jarch) then
    print_status('PASS', 'already installed', show_new_only)
  
  else -- Perform install.

    -- Iterate over dependencies first:
    for dep_rockname, dep_rockversion in pairs(info.require) do
      -- TODO: We need to add support for packages not in luarocks.
      if dep_rockname ~= 'luajit' then
        -- Dependent rock must fail as well, we cannot determine 'require'.
        local dep_info = pkgu.infobest(repo, dep_rockname, 
          dep_rockversion)
        if not dep_info then
          local save_exclude = id_logger(rock_exclude_sys, rockname, 
            rockversion)
          local dependency = { 
            rock_name    = dep_rockname, 
            rock_version = dep_rockversion,
          }
          save_exclude('dependency_unavailable', dependency)
          print_status('FAIL', 'dependency not available', show_new_only)
          return save_pass(rockname, rockversion, false)
        end
        local ok = install(repo, dep_rockname, dep_info.version, level + 1)
        if not ok then
          local save_exclude = id_logger(rock_exclude_sys, rockname, 
            rockversion)
          local dependency = { 
            rock_name = dep_rockname, 
            rock_version = dep_info.version,
          }
          save_exclude('dependency_failure', dependency)
          print_status('FAIL', 'failure in dependency', show_new_only)
          return save_pass(rockname, rockversion, false)
        end
      end
    end

    -- Actual Luarock install:
    pkgu.emptydir(dir.luarockstree)
    local installed_paths, stderr = changed_paths(dir.luarockstree, 
      install_rock, rockname, rockversion)
    if not installed_paths then
      print_status('FAIL', 'luarocks install error :'..stderr)
      return save_pass(rockname, rockversion, false)
    end
    to_unix_eol(installed_paths)

    if not check_has_files(installed_paths, rockname, rockversion) then
      print_status('FAIL', 'no installed files')
      return save_pass(rockname, rockversion, false)
    end

    local modules, modules_err = modules_links(installed_paths, rockname, 
      rockversion)
    if not modules then
      print_status('FAIL', modules_err)
      return save_pass(rockname, rockversion, false)
    end

    -- TODO: Check bundle and pattern and allow if so:
    local module_conflict = has_module_conflict(modules, rockname, rockversion) 
    if module_conflict then
      print_status('FAIL', 'module conflict :'..module_conflict)
      return save_pass(rockname, rockversion, false)
    end

    local save_modules_list = logger(rock_modules, rockname, rockversion)
    local modules_list = array_to_true(keys_to_array(modules))
    save_modules_list(modules_list)

    local meta = get_meta(info, modules, rockname, rockversion, repo)

    local copy_links_ok, copy_links_err = copy_modules_links(modules, rockname, 
      rockversion)
    if not copy_links_ok then
      print_status('FAIL', copy_links_err)
      return save_pass(rockname, rockversion, false)
    end
    copy_modules_meta(meta, rockname, rockversion)

    save_pass(rockname, rockversion, true)

    print_status('PASS')

  end -- End of perform install.

  local has_installed_unstable = info == vinfo[1]
  if als_install_unstable and not has_installed_unstable then
    -- Install also latest unstable; not a dependency: it is fine if it fails.
    install(repo, rockname, vinfo[1].version)
  end

  return true
end

local function modules_of_rockname(rockname, upkgversion)
  local rockversion = to_rock_version(rockname, upkgversion)
  local modules = assert(getvarg(rock_modules, rockname, rockversion))
  return modules
end

local function all_os_pass(oses)
  return getvarg(oses, 'Windows', 'x86')
     and getvarg(oses, 'Linux',   'x86')
     and getvarg(oses, 'OSX',     'x86')
     and getvarg(oses, 'Windows', 'x64')
     and getvarg(oses, 'Linux',   'x64')
     and getvarg(oses, 'OSX',     'x64')
end

-- TODO: 2 phases, non-bundles (as of now) and bundles, separately.
-- bundles:
-- 1. consider all modules in the bundle, latest version only
-- 2. compute has based on names and strings
-- 3. if hash different 
--   31. create __boundle/rootname/incrversion and copy (handle __, collisions)
--   32. crate aggregated __meta.lua
--   33. zip
local function rock_finalize()
  for rockname, upkgversions in pairs(rock_pass) do
    for upkgversion, os_arch_pass in pairs(upkgversions) do
      if all_os_pass(os_arch_pass) then
        local modules = modules_of_rockname(rockname, upkgversion)
        local cd_dir = D(dir.luarocks_package, rockname, upkgversion)
        for modulename in pairs(modules) do
          local basename = modulename..'~'..upkgversion
          local zip_file = D(dir.package_zip, basename..'.zip')
          local lua_file = D(dir.package_zip, basename..'.lua')
          if not file_exist(zip_file) then
            local zipcmd = 'cd '..cd_dir
                        ..' && '..cmd.zip..' '..zip_file..' '..modulename
                        .. ' -x "*/\\.*"'
            assert(execute(zipcmd, dir.null, dir.null) == 0)
            local meta_code = file_read(D(cd_dir, modulename, '__meta.lua'))
            file_write(lua_file, meta_code)
            print('ADD', modulename, upkgversion)
          end        
        end
      end
    end
  end
end

--------------------------------------------------------------------------------
-- TODO: Allow working with more than 1 simple non-nested directory.
local function finalize(path)
  local meta_content = file_read(D(path, '__meta.lua'))
  local meta = deserialize(meta_content)
  local version = assert(meta.version)
  local name = assert(meta.name)
  assert(meta.require)
  assert(meta.homepage)
  assert(meta.description)
  local basename = name..'~'..version
  local zip_file  = D(dir.package_zip, basename..'.zip')
  local lua_file = D(dir.package_zip, basename..'.lua')
  if file_exist(zip_file) or file_exist(lua_file) then
    print('Package already present, overwrite?')
    local ok = pkgu.confirm()
    if not ok then
      return
    end
  end
  local tmp_dir = D(os.getenv('LUA_ROOT'), 'host', 'tmp')
  local tmp_name_dir = D(tmp_dir, name)
  pkgu.emptydir(tmp_name_dir)
  lfs.rmdir(tmp_name_dir)
  lfs.mkdir(tmp_name_dir)
  local current_dir = lfs.currentdir()
  local zipcmd =' cp -a '..path..' '..tmp_name_dir
              ..' && cd '..tmp_dir 
              ..' && '..cmd.zip..' '..zip_file..' '..name..' -x "*/\\.*"'
              ..' && cd '..current_dir
  assert(execute(zipcmd, dir.null, dir.null) == 0)
  file_write(lua_file, meta_content)
end

local function update_repo()
  local repo = { }
  for file in lfs.dir(dir.package_zip) do
    if file:sub(-4, -1) == '.lua' and file:sub(1, 2) ~= '__' then
      local name, version = unpack(split(file:sub(1, -5), '~'))
      local info = deserialize(file_read(D(dir.package_zip, file)))
      assert(pkgu.tover(version) == info.version)
      pkgu.infoinsert(repo, name, info)
    end
  end
  pkgu.checkrepo(repo)
  file_write(D(dir.package_zip, '__repo.lua'), serialize(repo))
end

-- Strings: name, link, name, description, versions.
local modules_body_fmt = [[
        <tr id ="%s"><td><a href="%s">%s</a></td><td>%s</td><td>%s</td></tr>
]]

--------------------------------------------------------------------------------
local function update_website_luarocks_packages()
  local repo = deserialize(file_read(D(dir.package_zip, '__repo.lua')))
  local names = keys_to_array(repo)
  table.sort(names, function(x, y) return x:lower() < y:lower() end)
  local modules = { }
  for i=1,#names do
    local name = names[i]
    local vinfo = repo[name]
    local versions = { }
    for j=1,#vinfo do 
      versions[j] = vinfo[j].version 
    end
    versions = table.concat(versions, '<br/>')
    local description = vinfo[1].description
    local homepage = vinfo[1].homepage
    modules[i] = modules_body_fmt:format(name, homepage, name, description, 
      versions) 
  end
  modules = table.concat(modules)
  local template = file_read(D(dir.website, 'luarocks_packages_template.html'))
  template = template:gsub('%${modules}', modules)
  file_write(D(dir.website, 'luarocks_packages.html'), template)
end

-- Strings: module, module, version, os, arch, pass, info.
local autobuild_body_fmt = [[
        <tr id="%s"><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>
]]

local function format_pass(s)
  if s then 
    return '<span style="color:green">yes</span>'
  else
    return '<span style="color:red">no</span>'
  end
end

local format_failure_dispatch = setmetatable({
  unsupported_external_library = function()
    return 'depends on external library', true
  end,
  not_valid_version_format = function(info)
    return 'rock version "'..info..'" is not <a href="http://semver.org/">semver</a> compatible'
  end,
  not_valid_version_format_of_dependency = function(info)
    return 'dependency version in "'..info..'" is not <a href="http://semver.org/">semver</a> compatible'
  end,
  module_conflict = function(info)
    return 'contending module "'..info.module_name..'" with "'..info.rock_name..'~'..info.rock_version..'"'
  end,
  file_os_conflict = function(_)
    return 'different .lua file for different OS'
  end,
  rock_download_error = function(_)
    return 'failed downloading rockspec'
  end,
  luarocks_install_error = function(_, rockname, rockversion, tos, tarch)
    local logaddr = D('luarocksorg', 'state', tos, tarch, 'log', rockname..'~'..rockversion)
    local logstdout = logaddr..'_out.txt'
    local logstderr = logaddr..'_err.txt' 
    return 'rock install failed, see: <a href="'..logstderr..'">stderr</a> and <a href="'..logstdout..'">stdout</a>'
  end,
  dependency_failure = function(info)
    return 'depends on failed '..info.rock_name..'~'..info.rock_version, true
  end,
  dependency_unavailable = function(info)
    return 'depends on unavailable '..info.rock_name..'~'..(info.rock_version or 'any'), true
  end,
  unsupported_os = function(_)
    return 'unsupported OS', true
  end,
  destination_already_set = function(_)
    return 'conflict between modulname.lua and modulename/init.lua'
  end,
  unexpected_files = function(_)
    return 'rock installs unexpected files'
  end,
}, { __index = function(_, k) error('NYI: '..k) end })

local function format_failure(rockname, upkgversion, erro, syserro, sysexcl, tos, tarch)
  local rockversion = to_rock_version(rockname, upkgversion)
  local id, info = has_error(erro, rockname, rockversion)
  if id then
    return format_failure_dispatch[id](info)
  end
  id, info = has_error(syserro, rockname, rockversion)
  if id then
    return format_failure_dispatch[id](info, rockname, rockversion, tos, tarch)
  end
  id, info = has_error(sysexcl, rockname, rockversion)
  if id then
    return format_failure_dispatch[id](info)
  end  
  error('cannot find error for '..rockname..'~'..rockversion..' '..tos..' '..tarch)
end

local function format_success(rockname, upkgversion, tos, tarch)
  local rockversion = to_rock_version(rockname, upkgversion)
  local logaddr = D('luarocksorg', 'state', tos, tarch, 'log', rockname..'~'..rockversion)
  local logstdout = logaddr..'_out.txt'
  local logstderr = logaddr..'_err.txt' 
  return 'rock install passed, see: <a href="'..logstderr..'">stderr</a> and <a href="'..logstdout..'">stdout</a>'
end

-- TODO: Consider both x86 and x64.
local function update_website_build()
  local pass = deserialize(file_read(D(dir.luarocks_state, 'pass.lua')))
  local erro = deserialize(file_read(D(dir.luarocks_state, 'error.lua')))
  local syserro, sysexcl = { }, { }
  for _,tos in ipairs{ 'Windows', 'OSX', 'Linux' } do
    syserro[tos] = { 
      x86 = deserialize(file_read(D(dir.luarocks_state, tos, 'x86', 'error_sys.lua'))),
      x64 = deserialize(file_read(D(dir.luarocks_state, tos, 'x64', 'error_sys.lua')))
    }
    sysexcl[tos] = { 
      x86 = deserialize(file_read(D(dir.luarocks_state, tos, 'x86', 'exclude_sys.lua'))),
      x64 = deserialize(file_read(D(dir.luarocks_state, tos, 'x64', 'exclude_sys.lua')))
    }
  end
  local names = keys_to_array(pass)
  table.sort(names, function(x, y) return x:lower() < y:lower() end)
  local state = { }
  for i=1,#names do
    local name = names[i]
    for version, oses in pairs(pass[name]) do 
      for tos,tarches in pairs(oses) do
        for tarch in pairs(tarches) do
          local tpass = format_pass(oses[tos][tarch])
          local info
          if not oses[tos][tarch] then -- Failure.
            local exclude
            info, exclude = format_failure(name, version, erro, syserro[tos][tarch], sysexcl[tos][tarch], tos, tarch)
            if exclude then
              tpass = '<span style="color:orange">excluded</span>'
            end
          else
            info = format_success(name, version, tos, tarch)
          end
          state[#state+1] = autobuild_body_fmt:format(name, name, version, tos, tarch, tpass, info)
        end
      end
    end
  end
  state = table.concat(state)
  local template = file_read(D(dir.website, 'luarocks_autobuild_template.html'))
  template = template:gsub('%${state}', state)
  file_write(D(dir.website, 'luarocks_autobuild.html'), template)
end

local function totime(path, what)
  local pathattr = lfs.attributes(path)
  local timestamp = assert(pathattr[what])
  local datestamp = os.date('*t', timestamp)
  return time.date(datestamp.year, datestamp.month, datestamp.day)
end

-- Strings: date, link, name, description, versions.
local updates_body_fmt = [[
        <tr><td>%s</td><td><a href="%s">%s</a></td><td>%s</td><td>%s</td></tr>
]]

local function update_website_index()
  local packages = { }
  for file in lfs.dir(dir.package_zip) do
    if file:sub(-4, -1) == '.lua' and file:sub(1, 2) ~= '__' then
      local info = deserialize(file_read(D(dir.package_zip, file)))
      local name, _ = unpack(split(file:sub(1, -5), '~'))
      info.name = info.name or name -- Old packages do not have the name field!
      local path = D(dir.package_zip, file)
      local filetime = totime(path, 'modification')
      packages[#packages + 1] = { filetime, info }
    end
  end
  table.sort(packages, function(x, y) return x[1] > y[1] end)
  local updates = { }
  for i=1,10 do
    local date = tostring(packages[i][1]):sub(1, 10)
    local info = packages[i][2]
    updates[i] = updates_body_fmt:format(date, info.homepage, info.name, info.description, info.version)
  end
  updates = table.concat(updates)
  local template = file_read(D(dir.website, 'index.template.html'))
  template = template:gsub('%${updates}', updates)
  file_write(D(dir.website, 'index.html'), template)
end

return {
  ['rock-list'] = function()
    local manifest = init_manifest()
    local rocknames = keys_to_array(manifest.repo)
    table.sort(rocknames)
    print(table.concat(rocknames, '\n'))
  end,
  ['rock-install'] = function(name, version)
    local manifest_repo = repo_from_manifest()
    install(manifest_repo, name, version)
  end,
  ['rock-install-all'] = function()
    local manifest_repo = repo_from_manifest()
    local rocknames = keys_to_array(manifest_repo)
    table.sort(rocknames)
    for i=1,#rocknames do   
      install(manifest_repo, rocknames[i])
    end
  end,
  ['rock-finalize'] = rock_finalize,
  ['finalize']      = finalize,
  ['update-repo']   = update_repo,
  ['update-website'] = function()
    update_website_luarocks_packages()
    update_website_build()
    update_website_index()
  end,
}
