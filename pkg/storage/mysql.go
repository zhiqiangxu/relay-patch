package storage

import (
	"time"

	// init mysql driver
	_ "github.com/go-sql-driver/mysql"
	"github.com/go-xorm/xorm"
	"github.com/zhiqiangxu/relay-patch/config"
)

// NewMySQL creates a new xorm.Engine
func NewMySQL(conf config.MySQLConfig) (*xorm.Engine, error) {

	db, err := xorm.NewEngine("mysql", conf.ConnectionString)
	if err != nil {
		return db, err
	}

	if conf.MaxOpenConn != 0 {
		db.SetMaxOpenConns(conf.MaxOpenConn)
	}

	if conf.MaxIdleConn != 0 {
		db.SetMaxIdleConns(conf.MaxIdleConn)
	}

	if conf.ConnMaxLifetime != 0 {
		db.SetConnMaxLifetime(time.Second * time.Duration(conf.ConnMaxLifetime))
	}

	if conf.ShowSQL {
		db.ShowSQL(true)
	}

	return db, nil
}
