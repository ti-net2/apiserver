package factory

import (
	"strings"

	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/mysqls/mysql"
	"k8s.io/apiserver/pkg/storage/storagebackend"

	_ "github.com/go-sql-driver/mysql"
	"github.com/golang/glog"
	dbmysql "github.com/jinzhu/gorm"
)

//connectionStr: user:password@tcp(host:port)/dbname
func newMysqlClient(connectionStr string, debug bool) (*dbmysql.DB, error) {
	var err error
	connStr := string(connectionStr) + string("?parseTime=True")
	db, err := dbmysql.Open(string("mysql"), connStr)
	if err != nil && !strings.Contains(err.Error(), "Unknown database") {
		return nil, err
	}

	conInfo := strings.Split(connectionStr, "/")

	onlyConStr := conInfo[0] + "/"
	databaseName := conInfo[1]
	glog.V(5).Infof("database connection %v name %v err %v", onlyConStr, databaseName, err)
	if err != nil {
		tmpDB, err := dbmysql.Open(string("mysql"), onlyConStr)
		if err != nil {
			return nil, err
		}

		if err = tmpDB.Exec("CREATE DATABASE " + databaseName).Error; err != nil {
			return nil, err
		}
		db, err = dbmysql.Open(string("mysql"), connStr)
		if err != nil && !strings.Contains(err.Error(), "Unknown database") {
			return nil, err
		}
	}
	if debug {
		db = db.Debug()
	}

	return db, db.DB().Ping()
}

func newMysqlStorage(c storagebackend.Config) (storage.Interface, DestroyFunc, error) {
	endpoints := c.Mysql.ServerList

	client, err := newMysqlClient(endpoints[0], c.Mysql.Debug)
	if err != nil {
		return nil, nil, err
	}

	destroyFunc := func() {
		client.Close()
	}

	return mysql.New(client, c.Codec, "v1", c.Mysql.ListDefaultLimit), destroyFunc, nil
}
