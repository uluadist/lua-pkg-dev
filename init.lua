local pkgu    = require 'pkg'.util
local xsys    = require 'xsys'
local lfs     = require 'lfs'
local serpent = require 'serpent'

-- TODO: Remove dependency on xsys.
local trim, split = xsys.string.trim, xsys.string.split
local append = xsys.table.append
local jos, jarch = jit.os, jit.arch

--[=[ CONFIGURATION EXAMPLE of ulua/host/config-dev.lua ------------------------

-- On Windows: install.bat /P C:/ste/luarocks /TREE C:/ste/luarockstree /L

local jos, jarch = jit.os, jit.arch

local function D(...)
  return table.concat({ ... }, '/')
end

local luarocks_address = 'http://rocks.luarocks.org/'

local update_manifest = false

local os_dir = {
  Windows = {
    null         = 'nul',
    package_zip  = 'where to store zip packages and lua metadata',
    luarocks     = 'where the intermediary output is stored',
    luarockstree = 'where luarocks tree is',
  },
  Linux = {
    null         = '/dev/null',
    package_zip  = 'where to store zip packages and lua metadata',
    luarocks     = 'where the intermediary output is stored',
    luarockstree = 'where luarocks tree is',
    customgcc    = 'where the custom gcc script is (to ensure flags)',
  },
  OSX = {
    null         = '/dev/null',
    package_zip  = 'where to store zip packages and lua metadata',
    luarocks     = 'where the intermediary output is stored',
    luarockstree = 'where luarocks tree is',
    customgcc    = 'where the custom gcc script is (to ensure flags)',
  }
}

local os_cmd = {
  Windows = {
    luarocks = 'luarocks executable',
    dos2unix = 'dos 2 unix EOL conversion executable',
    zip      = 'zip executable',
  },
  Linux = {
    luarocks = 'luarocks executable',
    dos2unix = 'dos 2 unix EOL conversion executable',
    zip      = 'zip executable',
  },
  OSX = {
    luarocks = 'luarocks executable',
    dos2unix = 'dos 2 unix EOL conversion executable',
    zip      = 'zip executable',
  }
}

local dir = os_dir[jos]
dir.luarocks_package    = D(dir.luarocks, 'package')
dir.luarocks_repository = D(dir.luarocks, 'repository')
dir.luarocks_state      = D(dir.luarocks, 'state')
dir.luarocks_state_sys  = D(dir.luarocks, 'state', jos, jarch)
dir.luarockstree_lua    = D(dir.luarockstree, 'share/lua/5.1')
dir.luarockstree_clua   = D(dir.luarockstree, 'lib/lua/5.1')
dir.luarockstree_bin    = D(dir.luarockstree, 'bin')
dir.luarockstree_extra  = D(dir.luarockstree, 'lib/luarocks/rocks')

local cmd = os_cmd[jos]
cmd.zip = cmd.zip..' -r'
cmd.luarocks = cmd.luarocks..' --deps-mode=none '
if dir.customgcc then
  assert(jos ~= 'Windows')
  cmd.luarocks = 'PATH='..dir.customgcc..':$PATH '..cmd.luarocks
end

return {
  luarocks_address = luarocks_address,
  update_manifest  = update_manifest,
  dir              = dir,
  cmd              = cmd,
}

-------------------------------------------------------------------------- ]=]--

-- TODO: Aggregate multiple luarocks into same package to solve some conflicts.
-- TODO: Implement external libraries handling.
-- TODO: Refactor: rock.name, rock.version.
-- TODO: Refactor: pass around save_error, save_error_sys.
-- TODO: File locking mechanism for concurrent operations.

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

local function file_read(filename)
  local f = assert(io.open(filename, 'rb'))
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

local config_filename = D(os.getenv('LUA_ROOT'), 'host', 'config-dev.lua')
local config = deserialize(file_read(config_filename))
local luarocks_address = config.luarocks_address
local update_manifest  = config.update_manifest
local dir              = config.dir
local cmd              = config.cmd

local function execute(command, fstdout, fstderr)
  local toexecute = command..' > '..fstdout..' 2> '..fstderr
  return os.execute(toexecute)
end

local function file_to_lines(filename)
  return split(file_read(filename), '\n')
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
local rock_pass = persistent(D(dir.luarocks_state, 'pass.lua'))

-- rockname -> rockversion -> modules -> true:
local rock_modules     = persistent(D(dir.luarocks_state, 'modules.lua'))

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
  for _,rocknames in pairs(kind) do
    for rockname,rockversions in pairs(rocknames) do
      for rockversion,_ in pairs(rockversions) do
        if rockname == targetrockname and rockversion == targetrockversion then 
          return true
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
local PKG_VER = 2
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

local function upkg_repo_valid(manifest_repository)
  local all_valid_versions = upkg_repo_all_valid_versions(manifest_repository)
  local valid = { }
  for rockname,rockversions in pairs(manifest_repository) do
    for rockversion,_ in pairs(rockversions) do
      local save_error     = id_logger(rock_error,     rockname, rockversion)
      local save_error_sys = id_logger(rock_error_sys, rockname, rockversion)

      local ok, err = is_valid_version(rockversion)
      if not ok then
        save_error('not_valid_version_format', err) 
        break 
      end

      ok, err =  download_rockspec(rockname, rockversion)
      if not ok then
         save_error('rock_download_error', err) 
         break
      end

      ok, err = load_downloaded_rockspec(rockname, rockversion)
      if not ok then
        save_error('rock_loadstring_error', err) 
        break
      end
      local rockspec = ok

      ok, err = is_supported_os(rockspec)
      if not ok then 
        save_error_sys('unsupported_os', err) 
        break
      end

      ok, err = is_supported_external_libraries(rockspec)
      if not ok then
        save_error('unsupported_external_library', err) 
        break
      end

      ok, err = is_supported_lua(rockspec)
      if not ok then
        save_error('unsupported_lua_version', err) 
        break
      end

      ok, err = is_valid_version_dependencies(rockspec)
      if not ok then
        save_error('not_valid_version_format_of_dependency', err)
        break
      end

      local dependencies = upkg_dependencies(rockspec, all_valid_versions)

      local description = rockspec.description
      -- To get actual __meta.lua it is still necessary to modify 'require' to 
      -- account for rockname -> { modules } and to add intra-dependencies 
      -- (same reason).
      local info = {
        version     = rockversion,
        require     = dependencies,
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
  local manifest_code
  if update_manifest then
    manifest_code = pkgu.download(luarocks_address, 'manifest')
    file_write(manifest_path, manifest_code)
  else
    manifest_code = file_read(manifest_path)
  end
  local manifest = load_config(manifest_code)
  return manifest
end

local function repo_from_manifest()
  local manifest = init_manifest()
  return upkg_repo_valid(manifest.repository)
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
      stdout = file_to_lines(logstdout), 
      stderr = file_to_lines(logstderr), 
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

-----------
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
          local save_error = id_logger(rock_error_sys, rockname, rockversion)
          save_error('destination_already_set', to)
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
    local save_error = id_logger(rock_error_sys, rockname, rockversion)
    save_error('unexpected_files', unmatched_array)
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

local function fix_require(modulemeta, repo)
  local fixed_require = { }
  for dep_name, dep_version in pairs(modulemeta.require) do
    if dep_name ~= 'luajit' and dep_name ~= 'pkg' then
      local info = assert(pkgu.infobest(repo, dep_name, dep_version))
      local target_version = info.version
      local modules = assert(getvarg(rock_modules, dep_name, target_version))
      for dep_modulename in pairs(modules) do
        fixed_require[dep_modulename] = dep_version
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
    fix_require(meta[modulename], repo)
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

local function status_printer(rockname, rockversion)
  assert(rockname and rockversion)
  return function(status, message)
    assert(status)
    local fixed_status = fixed_width(status, 8)
    local fixed_name_version = fixed_width(rockname..'~'..rockversion, 32)
    io.write(fixed_status, ' : ', fixed_name_version)
    if message then
      io.write(' : ', message)
    end
    io.write('\n')
  end
end

local function save_pass(rockname, rockversion, status)
  local upkgversion = to_upkg_version(rockname, rockversion)
  local save = logger(rock_pass, rockname, upkgversion)
  save(status, jos, jarch)
  return status
end

local function install(repo, rockname, rockversion)
  local print_status = status_printer(rockname, rockversion or '<latest>')
  print_status('START')

  local als_install_unstable = not rockversion

  local vinfo = repo[rockname]
  if not vinfo then
    print_status('FAIL', 'unavailable rock')
    return nil
  end

  local info = pkgu.infobest(repo, rockname, rockversion)
  if not info then
    print_status('FAIL', 'unavailable rock version')
    return nil
  end

  rockversion = rockversion or info.version
  print_status = status_printer(rockname, rockversion)

  -- Has to be before rock_pass check because subsequent OS-specific build
  -- can set an error in rock_error due to filename differences.
  if has_error(rock_error,     rockname, rockversion) or
     has_error(rock_error_sys, rockname, rockversion) then
     print_status('FAIL', 'previous failure')
     -- Necessary to update this as runs on other OS might have set failure 
     -- in rock_error:
     return save_pass(rockname, rockversion, false)
     -- Notice that some OS will not be true nor false as unsupported OS 
     -- rocks installs are not even attampted (repo exclusion).
  end

  local upkversion = to_upkg_version(rockname, rockversion)
  if getvarg(rock_pass, rockname, upkversion, jos, jarch) then
    print_status('PASS', 'already installed')
  
  else -- Perform install.

    for dep_rockname, dep_rockversion in pairs(info.require) do
      -- TODO: We need to add support for packages not in luarocks.
      if dep_rockname ~= 'luajit' then
        -- Dependent rock must fail as well, we cannot determine 'require'.
        print_status('REQUIRE')
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
          print_status('FAIL', 'dependency not available')
          return save_pass(rockname, rockversion, false)
        end
        local ok = install(repo, dep_rockname, dep_info.version)
        if not ok then
          local save_exclude = id_logger(rock_exclude_sys, rockname, 
            rockversion)
          local dependency = { 
            rock_name = dep_rockname, 
            rock_version = dep_info.version,
          }
          save_exclude('dependency_failure', dependency)
          print_status('FAIL', 'failure in dependency')
          return save_pass(rockname, rockversion, false)
        end
      end
    end

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
  return getvarg(oses, 'Windows', jarch)
     and getvarg(oses, 'Linux',   jarch)
     and getvarg(oses, 'OSX',     jarch)
end

local function update_package_zip()
  for rockname, upkgversions in pairs(rock_pass) do
    for upkgversion, os_arch_pass in pairs(upkgversions) do
      if all_os_pass(os_arch_pass) then
        local modules = modules_of_rockname(rockname, upkgversion)
        local cd_dir = D(dir.luarocks_package, rockname, upkgversion)
        for modulename in pairs(modules) do
          local basename = modulename..'~'..upkgversion
          local zip_file = D(dir.package_zip, basename..'.zip')
          local lua_fule = D(dir.package_zip, basename..'.lua')
          if not file_exist(zip_file) then
            local zipcmd = 'cd '..cd_dir
                        ..' && '..cmd.zip..' '..zip_file..' '..modulename
                        .. ' -x "*/\\.*"'
            assert(execute(zipcmd, dir.null, dir.null) == 0)
            local meta_code = file_read(D(cd_dir, modulename, '__meta.lua'))
            file_write(lua_fule, meta_code)
          end        
        end
      end
    end
  end
end

-- TODO: Allow working with more than 1 simple non-nested directory.
local function finalize(name)
  if name:sub(-1, -1) == '/' then
    name = name:sub(1, -2)
  end
  assert(not name:find('/'))
  local meta_content = file_read(D(name, '__meta.lua'))
  local meta = deserialize(meta_content)
  local dir_version = meta.version
  local basename = name..'~'..dir_version
  local zip_file  = D(dir.package_zip, basename..'.zip')
  local lua_file = D(dir.package_zip, basename..'.lua')
  assert(not file_exist(zip_file))
  assert(not file_exist(lua_file))
  local zipcmd = cmd.zip..' '..zip_file..' '..name..' -x "*/\\.*"'
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

return {
  rock_list = function()
    local manifest = init_manifest()
    local rocknames = keys_to_array(manifest.repo)
    table.sort(rocknames)
    print(table.concat(rocknames, '\n'))
  end,
  rock_install = function(name, version)
    local manifest_repo = repo_from_manifest()
    install(manifest_repo, name, version)
  end,
  rock_install_all = function()
    local manifest_repo = repo_from_manifest()
    local rocknames = keys_to_array(manifest_repo)
    table.sort(rocknames)
    for i=1,#rocknames do   
      install(manifest_repo, rocknames[i])
      io.write('\n')
    end
  end,
  rock_finalize = update_package_zip,
  finalize      = finalize,
  update_repo   = update_repo,
}
