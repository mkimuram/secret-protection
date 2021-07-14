 FROM gcr.io/distroless/static:latest
 LABEL maintainers="Kubernetes Authors"
 LABEL description="Secret protection controller"
 ARG binary=./bin/secret-protection-controller

 COPY ${binary} secret-protection-controller
 ENTRYPOINT ["/secret-protection-controller"]
