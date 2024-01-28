package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/constant"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
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

func main() {
	// dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8&parseTime=True&loc=Local", "user", "password", "127.0.0.1", "3306", "database")
	// db, err := gorm.Open(mysql.New(mysql.Config{
	// 	DSN: dsn,
	// }))
	// if err != nil {
	// 	fmt.Errorf("gorm.Open", err)
	// }
	// adapter, err := gormadapter.NewAdapterByDBWithCustomTable(db, &CasbinRule{})
	// if err != nil {
	// 	fmt.Errorf("gormadapter.NewAdapterByDBWithCustomTable", err)
	// }
	// if err := db.Exec("ALTER TABLE casbin_rule CHANGE `created_at` `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP").Error; err != nil {
	// 	fmt.Errorf("db.Exec", err)
	// }
	// if err := db.Exec("ALTER TABLE casbin_rule CHANGE `updated_at` `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP").Error; err != nil {
	// 	fmt.Errorf("db.Exec", err)
	// }
	e, err := casbin.NewEnforcer("model_my.conf")
	if err != nil {
		fmt.Errorf("casbin.NewEnforcer", err)
	}
	e.SetFieldIndex("p", constant.SubjectIndex, 0)
	e.SetFieldIndex("p", constant.ObjectIndex, 1)
	// e.SetFieldIndex("p", constant.SubjectIndex, 0)
	// e.SetFieldIndex("p", constant.DomainIndex, 1)
	// e.SetFieldIndex("p", constant.ObjectIndex, 2)

	adapter := fileadapter.NewAdapter("policy_my.csv")
	e.SetAdapter(adapter)

	if err := e.LoadPolicy(); err != nil {
		fmt.Errorf("LoadPolicy", err)
	}

	fmt.Println()
	r, _ := e.GetImplicitPermissionsForUser("user:sonnie")
	j, _ := json.Marshal(r)
	fmt.Println("GetImplicitPermissionsForUser: ", string(j))

	fmt.Println()
	r2, _ := e.GetImplicitPermissionsForUser("user:ian")
	j2, _ := json.Marshal(r2)
	fmt.Println("GetImplicitPermissionsForUser: ", string(j2))

	fmt.Println()
	j3, _ := json.Marshal(e.GetAllObjects())
	fmt.Println("GetAllObjects: ", string(j3))

	fmt.Println()
	j4, _ := json.Marshal(e.GetAllNamedSubjects("p"))
	fmt.Println("GetAllNamedSubjects: ", string(j4))

	fmt.Println()
	j5, _ := json.Marshal(e.GetAllNamedRoles("g"))
	fmt.Println("GetAllNamedRoles: ", string(j5))

	fmt.Println()
	j6, _ := json.Marshal(e.GetAllActions())
	fmt.Println("GetAllActions: ", string(j6))

	fmt.Println()
	j7_, _ := e.GetUsersForRole("role:admin_member")
	j7, _ := json.Marshal(j7_)
	fmt.Println("GetUsersForRole: ", string(j7))

	// j8, _ := json.Marshal(e.GetAllUsersByDomain("dom:marketing"))
	// fmt.Println("GetUsersForRole: ", string(j8))

	// e.SetAdapter(adapter)

	// e.AddPolicy(params ...interface{})
}
