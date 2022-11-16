FROM harbor.k-space.ee/k-space/microservice-base
RUN pip3 install asyncinotify ujson prometheus-async[aiohttp]
WORKDIR /app
ADD heuristics.py /app/heuristics.py
ADD log_shipper.py /app/log_shipper.py
ENTRYPOINT /app/log_shipper.py
