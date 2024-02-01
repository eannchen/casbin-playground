package account

import (
	"fmt"

	"github.com/casbin/casbin/v2"
)

func Account() {
	e, err := casbin.NewEnforcer(
		"account/account.conf",
		"account/account.csv",
	)
	if err != nil {
		fmt.Errorf("casbin.NewEnforcer", err)
	}

	if err := e.LoadPolicy(); err != nil {
		fmt.Errorf("LoadPolicy", err)
	}

	fmt.Println()
	ok, err := e.Enforce("company:-1", "division:0")
	if err != nil {
		fmt.Errorf("e.Enforce", err)
	}
	fmt.Printf("%+v", ok)
}
