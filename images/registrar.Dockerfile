FROM scratch
COPY csi-node-driver-registrar /csi-node-driver-registrar
COPY licenses/ /usr/share/licenses/csi/
ENTRYPOINT ["/csi-node-driver-registrar"]
