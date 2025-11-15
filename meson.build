project('irssi-fe-web', 'c',
  version : '1.0.0',
  meson_version : '>=0.53',
  default_options : ['warning_level=1'])

cc = meson.get_compiler('c')

# Dependencies
glib_dep = dependency('glib-2.0', version : '>=2.32')
openssl_dep = dependency('openssl', version : '>=1.1.0')

# Find irssi headers
irssi_include = get_option('irssi_include')
if irssi_include == ''
  # Try to find irssi via pkg-config
  irssi_dep = dependency('irssi', required : false)
  if irssi_dep.found()
    irssi_include = irssi_dep.get_variable(pkgconfig : 'includedir')
  else
    # Try common locations
    foreach dir : ['/usr/include/irssi', '/usr/local/include/irssi', 
                   '/opt/homebrew/include/irssi', '/opt/local/include/irssi']
      if cc.has_header('src/common.h', args : '-I' + dir)
        irssi_include = dir
        break
      endif
    endforeach
  endif
endif

if irssi_include == ''
  error('Cannot find irssi headers. Use -Dirssi_include=/path/to/irssi/include')
endif

message('Using irssi headers from: ' + irssi_include)

# Module installation directory
prefix = get_option('prefix')
if prefix == '/usr' or prefix == '/usr/local'
  # System installation
  moduledir = get_option('libdir') / 'irssi' / 'modules'
else
  # User installation (default: ~/.local)
  moduledir = prefix / 'lib' / 'irssi' / 'modules'
endif

message('Module will be installed to: ' + prefix / moduledir)

# Include directories
rootinc = include_directories(irssi_include)

# Module suffix (platform-specific)
module_suffix = []
if host_machine.system() == 'darwin'
  module_suffix = 'so'
endif

# Build subdirectory
subdir('src')

# Summary
summary({
  'Version': meson.project_version(),
  'irssi headers': irssi_include,
  'Install prefix': prefix,
  'Module directory': prefix / moduledir,
}, section: 'Configuration')
