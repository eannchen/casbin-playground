package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/constant"
	gormadapter "github.com/casbin/gorm-adapter/v3"
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

func main() {
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

	// e, err := casbin.NewEnforcer("model_my.conf", "policy_my.csv")
	// e, err := casbin.NewEnforcer("model_my.conf", adapter)
	e, err := casbin.NewEnforcer("model_my.conf")
	if err != nil {
		fmt.Errorf("casbin.NewEnforcer", err)
	}
	e.SetFieldIndex("p", constant.SubjectIndex, 0)
	e.SetFieldIndex("p", constant.DomainIndex, 1)
	e.SetFieldIndex("p", constant.ObjectIndex, 2)

	e.SetAdapter(adapter)

	if err := e.GetAdapter().(*gormadapter.Adapter).LoadFilteredPolicy(e.GetModel(), gormadapter.Filter{
		// V0: []string{"role:admin"},
		V1: []string{"dom:admin"},
		// V2: []string{"dom:admin"},
		// V2: []string{"obj:account_admin"},
		// V3: []string{"act:all"},
		// V4: []string{"allow"},
	}); err != nil {
		fmt.Errorf("LoadFilteredPolicy", err)
	}
	// migrate(e) // will also load policy

	// if err := e.LoadPolicy(); err != nil {
	// 	fmt.Errorf("LoadPolicy", err)
	// }

	fmt.Println(e.GetPolicy())
	fmt.Println(e.GetNamedGroupingPolicy("g"))
	fmt.Println(e.GetNamedGroupingPolicy("g2"))
	fmt.Println(e.GetNamedGroupingPolicy("g3"))

	// fmt.Println()
	// j, _ := json.Marshal(e.GetPermissionsForUserInDomain("user:ian", "dom:marketing"))
	// fmt.Println("GetPermissionsForUserInDomain: ", string(j))

	// fmt.Println()
	// j1, _ := json.Marshal(e.GetPermissionsForUserInDomain("user:ian", "dom:admin"))
	// fmt.Println("GetPermissionsForUserInDomain: ", string(j1))

	// fmt.Println()
	// j2, _ := json.Marshal(e.GetPermissionsForUser("user:ian", "dom:admin", "dom:marketing"))
	// fmt.Println("GetPermissionsForUser: ", string(j2))

	// fmt.Println()
	// r, _ := e.GetRolesForUser("user:ian", "dom:admin")
	// fmt.Println("GetRolesForUser: ", r)

	// fmt.Println()
	// r1, _ := e.GetRolesForUser("user:ian", "dom:marketing")
	// fmt.Println("GetRolesForUser: ", r1)

	// fmt.Println()
	// if ok, err := e.Enforce("user:ian", "dom:admin", "obj:account_admin", "act:read"); err != nil {
	// 	fmt.Errorf("Enforce err: ", err)
	// } else {
	// 	fmt.Println(ok)
	// }
	// fmt.Println()
	// if ok, err := e.Enforce("user:ian", "dom:admin", "subscription:exhibition", "act:read"); err != nil {
	// 	fmt.Errorf("Enforce err: ", err)
	// } else {
	// 	fmt.Println(ok)
	// }

	// if _, err := e.AddNamedGroupingPolicy("g", []string{"user:sonnie", "role:organiser", "dom:guest"}); err != nil {
	// 	fmt.Errorf("e.AddNamedGroupingPolicy", err)
	// }
	fmt.Println()
	if ok, err := e.Enforce("user:sonnie", "dom:guest", "obj:news", "act:create_limited"); err != nil {
		fmt.Println("Enforce err: ", err)
	} else {
		fmt.Println(ok)
	}
	fmt.Println()
	if ok, err := e.Enforce("user:sonnie", "dom:guest", "obj:news", "act:create"); err != nil {
		fmt.Println("Enforce err: ", err)
	} else {
		fmt.Println(ok)
	}
}

func migrate(e *casbin.Enforcer) error {
	records := readCsvFile("policy_my.csv")
	// fmt.Println(records)
	return e.GetAdapter().(*gormadapter.Adapter).Transaction(e, func(e casbin.IEnforcer) error {
		for _, record := range records {
			if strings.HasPrefix(record[0], "p") {
				e.AddPolicy(record[1:])
			} else if strings.HasPrefix(record[0], "g") {
				e.AddNamedGroupingPolicy(record[0], record[1:])
			}
		}
		return nil
	})
}

func readCsvFile(filePath string) [][]string {
	f, err := os.Open(filePath)
	if err != nil {
		log.Fatal("Unable to read input file "+filePath, err)
	}
	defer f.Close()

	csvReader := csv.NewReader(f)
	csvReader.TrimLeadingSpace = true
	csvReader.FieldsPerRecord = -1
	records, err := csvReader.ReadAll()
	if err != nil {
		log.Fatal("Unable to parse file as CSV for "+filePath, err)
	}

	return records
}
