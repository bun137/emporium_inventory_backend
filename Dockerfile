FROM golang:1.23
WORKDIR /emporium/backend


# Copy Go module files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire backend source code
COPY . .


EXPOSE 7575 

RUN go build .
CMD ["/emporium/backend/emporium_inventory_backend"]
