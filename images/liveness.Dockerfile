FROM scratch
COPY livenessprobe /livenessprobe
COPY licenses/ /usr/share/licenses/csi/
ENTRYPOINT ["/livenessprobe"]
