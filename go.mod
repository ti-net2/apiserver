// This is a generated file. Do not edit directly.

module k8s.io/apiserver

go 1.16

require (
	github.com/NYTimes/gziphandler v1.1.1 // indirect
	github.com/aws/aws-sdk-go v1.43.23
	github.com/coreos/go-oidc v2.1.0+incompatible
	github.com/coreos/go-systemd/v22 v22.3.2
	github.com/davecgh/go-spew v1.1.1
	github.com/emicklei/go-restful v2.9.5+incompatible
	github.com/evanphx/json-patch v4.12.0+incompatible
	github.com/fsnotify/fsnotify v1.4.9
	github.com/go-openapi/jsonreference v0.19.5 // indirect
	github.com/go-openapi/swag v0.19.14 // indirect
	github.com/go-sql-driver/mysql v1.6.0
	github.com/gogo/protobuf v1.3.2
	github.com/google/go-cmp v0.5.5
	github.com/google/gofuzz v1.1.0
	github.com/google/uuid v1.1.2
	github.com/googleapis/gnostic v0.5.5
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/jinzhu/gorm v1.9.16
	github.com/mattn/go-sqlite3 v1.14.12
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822
	github.com/pquerna/cachecontrol v0.0.0-20171018203845-0dec1b30a021 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.7.0
	go.etcd.io/etcd/api/v3 v3.5.0
	go.etcd.io/etcd/client/pkg/v3 v3.5.0
	go.etcd.io/etcd/client/v3 v3.5.0
	go.etcd.io/etcd/server/v3 v3.5.0
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.20.0
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.20.0
	go.opentelemetry.io/otel v0.20.0
	go.opentelemetry.io/otel/exporters/otlp v0.20.0
	go.opentelemetry.io/otel/sdk v0.20.0
	go.opentelemetry.io/otel/trace v0.20.0
	go.uber.org/zap v1.19.0
	golang.org/x/crypto v0.0.0-20210817164053-32db794688a5
	golang.org/x/net v0.0.0-20220127200216-cd36cc0744dd
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/sys v0.0.0-20211216021012-1d35b9e2eb4e
	google.golang.org/grpc v1.40.0
	gopkg.in/mgo.v2 v2.0.0-20190816093944-a6b53ec6cb22
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/square/go-jose.v2 v2.2.2
	k8s.io/api v0.0.0-20220222194917-a6b22073a6bd
	k8s.io/apimachinery v0.0.0-20220124172104-276a8a7530a3
	k8s.io/client-go v0.0.0-20220124173639-0f7ee7041f40
	k8s.io/component-base v0.0.0-20220124174242-95a6431a4277
	k8s.io/klog v1.0.0
	k8s.io/klog/v2 v2.30.0
	k8s.io/kube-openapi v0.0.0-20211115234752-e816edb12b65
	k8s.io/utils v0.0.0-20211116205334-6203023598ed
	sigs.k8s.io/apiserver-network-proxy/konnectivity-client v0.0.30
	sigs.k8s.io/json v0.0.0-20211020170558-c049b76a60c6
	sigs.k8s.io/structured-merge-diff/v4 v4.2.1
	sigs.k8s.io/yaml v1.2.0
)

replace (
	k8s.io/api => k8s.io/api v0.0.0-20220222194917-a6b22073a6bd
	k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20220124172104-276a8a7530a3
	k8s.io/client-go => k8s.io/client-go v0.0.0-20220124173639-0f7ee7041f40
	k8s.io/component-base => k8s.io/component-base v0.0.0-20220124174242-95a6431a4277
)
