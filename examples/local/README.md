# Local example

Applies circuit-openldap to a throwaway Rocky Linux 10 container with systemd. You need Conn3x and Podman.

```sh
./up.sh
export TF_VAR_root_password=$(openssl rand -hex 12)
conn3x init
conn3x apply
conn3x plan
```

The second plan says `No changes.` slapd listens on `127.0.0.1:389` inside the container. To bind as the root DN and list the directory, which holds `ou=people`, `ou=groups` and the person and group from `main.tf`:

```sh
ssh -p 2311 -i id_ed25519 -o UserKnownHostsFile=known_hosts root@127.0.0.1 \
  "ldapsearch -x -LLL -H ldap://127.0.0.1 -D cn=admin,dc=example,dc=test -w '$TF_VAR_root_password' -b dc=example,dc=test dn"
```

The same search without `-D` and `-w` is refused: anonymous binds are off.

Set a new `TF_VAR_root_password` and apply again to change the root password.

`up.sh` listens on `127.0.0.1:2311`. Set `PORT` to use another port, and pass the same port to Conn3x with `-var port=PORT`. Set `CONTAINERFILE` to test another distro, such as one of the images in Conn3x's `test/images`, which CI uses.

`./down.sh` removes the container, its volumes, the key and the state.
