# ModSec2elastic
Streaming ModSecurity Logs into Elastic Search Instance

# install

```sh
$ npm install
```

# run

first change the connection string inside the file 'connection.js' to point to your ELK, and ten
```sh
$ node app.js
```

# TODO

1. Connection string as Env. Variable
2. Extend to SSHLogs
