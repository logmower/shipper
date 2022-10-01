FROM harbor.k-space.ee/k-space/microservice-base
RUN pip3 install asyncinotify ujson
ADD log_shipper.py /log_shipper.py
ENTRYPOINT /log_shipper.py
