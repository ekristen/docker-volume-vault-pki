# Vault PKI Backend Docker Volume Plugin

This is a Docker Plugin V2 that is **WIP** for Docker v1.12.2+ (experimental) and later ... 

This currently does not work as the V2 plugin support does not setup networking properly, so even the example of sshfs does not work in the official documentation.

The idea behind this plugin is simple, you can create a docker volume that once mounted sends an issue request to a Vault PKI backend and writes the results of that response to a docker volume.

## Notes

* Mount /var/run/docker.sock in plugin and SIGHUP when PKI is renewed so that an application could choose to reload? 
* Once plugin configuration is enabled, then allow vault addr and vault token to be configured for the entire plugin
* Allow for approle login vs just token login
* Plugin needs to renew/or request new PKI credentials before or after they expire.

## License

[MIT](LICENSE.md)

For all vendor libraries see their respective repositories for their Licenses.
