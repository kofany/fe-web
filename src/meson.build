# Source files for fe-web module

fe_web_sources = files(
  'fe-web.c',
  'fe-web-client.c',
  'fe-web-server.c',
  'fe-web-signals.c',
  'fe-web-utils.c',
  'fe-web-json.c',
  'fe-web-websocket.c',
  'fe-web-ssl.c',
  'fe-web-crypto.c',
  'fe-web-netserver.c',
)

# Build shared module
shared_module('fe_web',
  fe_web_sources,
  include_directories : rootinc,
  name_suffix : module_suffix,
  dependencies : [glib_dep, openssl_dep],
  install : true,
  install_dir : moduledir,
)
