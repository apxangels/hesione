[![Docker Hub](https://img.shields.io/badge/Docker%20Hub-hesione-blue?logo=docker)](https://hub.docker.com/r/duoluotianshi/hesione)

# Hesione
Hesione (in Ancient Greek Ἡσιονη) was the daughter of Oceanus, the wife of Prometheus and the mother of Deucalion </br>
In fact, this proxy makes it possible to separate requests from different Grafana organizations to Prometheus or VictoriaMetrics, ensuring that metrics are not accessible to unauthorized parties.
An app for enrich promql requests with labels. It helps build data sources separated by labels for applications like Grafana or similar. Within a single Grafana organization, you can configure metric visibility scopes even within a single VictoriaMetrics cluster account or a single Prometheus instance. </br>
Basically, this is an another implementation of the idea of [Prometheus issue #1813](https://github.com/prometheus/prometheus/issues/1813).
## App health
You can check the status of the application and backends (promql apps) at the `/health` endpoint.
## Config 
Example located in config.yml
### Receivers and locations
When a receiver is defined, an endpoint is automatically created on the proxy that can be accessed. For example, if the receiver name is vmcluster, the endpoint will be available at: `hesione:8000/vmcluster`
The `prom` key specifies the URL of the Prometheus (or VictoriaMetrics) instance that the proxy will forward the requests to.

### Pass policy 
If the `auth` field is specified, it sets up authentication for the proxy itself.
If the `prom_auth` field is specified, it is used as basic authentication when forwarding requests to Prometheus.
If `auth: preserve` is set, the proxy will require the same credentials as defined in `prom_auth` for access, and those credentials will also be used when forwarding requests to Prometheus.

## Fast start
### Without docker
```
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
You should able to see the app on http://localhost:8000 

### With docker / docker compose
You can build it by yourself:
```
docker build -t hesione .

docker run -d \
  --name hesione \
  -p 8000:8000 \
  -v $(pwd)/config.yaml:/app/config.yaml \
  hesione
```
or use compose
```
docker compose up -d
```
Or download from hub:
```
docker pull duoluotianshi/hesione:latest
```
