## a webserver project base on dpfs and dpfs client
# to start the web
```
cd thirdparty/dpfs-app
npm start
```

# to start the server
```
cd app/server
./dserver --ak <ai api key> --connStr <dpfs storage system's ip:port>
```

# port range
```
dpfs storage: 20500,
mysql database: 3306,
dpfs-backend: 20510,
dpfs-web: 3000,
dpfs-agent-backend: 20520,
dpfs-agent-vector-service: {
    vector-search: 20530,
    qdrant-service: 20531-20532
    redis: 20533
}
hermes-dpfs-agent-backend: 20564
```
