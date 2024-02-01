package db

import (
	"fmt"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/constant"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/pkg/errors"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type CasbinRule struct {
	ID    uint   `gorm:"primaryKey;autoIncrement"`
	Ptype string `gorm:"type:varchar(15);uniqueIndex:unique_index"`
	V0    string `gorm:"type:varchar(100);uniqueIndex:unique_index"`
	V1    string `gorm:"type:varchar(100);uniqueIndex:unique_index"`
	V2    string `gorm:"type:varchar(100);uniqueIndex:unique_index"`
	V3    string `gorm:"type:varchar(100);uniqueIndex:unique_index"`
	V4    string `gorm:"type:varchar(100);uniqueIndex:unique_index"`
	V5    string `gorm:"type:varchar(100);uniqueIndex:unique_index"`

	CreatedAt time.Time
	UpdatedAt time.Time
}

func newEnforcerByDB() (e *casbin.Enforcer, err error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8&parseTime=True&loc=Local", "user", "password", "127.0.0.1", "3306", "database")
	db, err := gorm.Open(mysql.New(mysql.Config{
		DSN: dsn,
	}))
	if err != nil {
		fmt.Errorf("gorm.Open", err)
	}
	adapter, err := gormadapter.NewAdapterByDBWithCustomTable(db, &CasbinRule{})
	if err != nil {
		fmt.Errorf("gormadapter.NewAdapterByDBWithCustomTable", err)
	}
	if err := db.Exec("ALTER TABLE casbin_rule CHANGE `created_at` `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP").Error; err != nil {
		fmt.Errorf("db.Exec", err)
	}
	if err := db.Exec("ALTER TABLE casbin_rule CHANGE `updated_at` `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP").Error; err != nil {
		fmt.Errorf("db.Exec", err)
	}

	e, err = casbin.NewEnforcer("model_my.conf")
	if err != nil {
		fmt.Errorf("casbin.NewEnforcer", err)
	}
	e.SetFieldIndex("p", constant.SubjectIndex, 0)
	e.SetFieldIndex("p", constant.DomainIndex, 1)
	e.SetFieldIndex("p", constant.ObjectIndex, 2)

	e.SetAdapter(adapter)

	if err := e.LoadPolicy(); err != nil {
		err = errors.Wrap(err, "LoadPolicy")
	}
	return

}
