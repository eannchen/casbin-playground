package main

import (
	"encoding/json"
	"fmt"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/constant"
)

func main() {

	e, err := casbin.NewEnforcer("model_my.conf", "policy_my.csv")
	if err != nil {
		fmt.Errorf("casbin.NewEnforcer", err)
	}
	// e.SetFieldIndex("p", constant.SubjectIndex, 0)
	// e.SetFieldIndex("p", constant.DomainIndex, 1)
	// e.SetFieldIndex("p", constant.ObjectIndex, 2)
	e.SetFieldIndex("p", constant.PriorityIndex, 0)
	e.SetFieldIndex("p", constant.SubjectIndex, 1)
	e.SetFieldIndex("p", constant.DomainIndex, 2)
	e.SetFieldIndex("p", constant.ObjectIndex, 3)

	if err := e.LoadPolicy(); err != nil {
		fmt.Errorf("LoadPolicy", err)
	}

	// fmt.Printf("GetAllRoles: %#v\n\n", e.GetAllRoles())
	// fmt.Printf("GetAllNamedRoles: %#v\n\n", e.GetAllNamedRoles("g"))
	// fmt.Printf("GetAllSubjects: %#v\n\n", e.GetAllSubjects())
	// fmt.Printf("GetAllNamedSubjects: %#v\n\n", e.GetAllNamedSubjects("p"))
	// fmt.Printf("GetAllObjects: %#v\n\n", e.GetAllObjects())
	// fmt.Printf("GetAllNamedObjects: %#v\n\n", e.GetAllNamedObjects("p"))

	j, _ := json.Marshal(e.GetPermissionsForUser("user:ian", "dom:marketing"))
	fmt.Println("GetPermissionsForUser", string(j))

	fmt.Println()
	if r, err := e.GetRolesForUser("user:ian", "dom:admin"); err != nil {
		fmt.Println("GetRolesForUser err: ", err)
	} else {
		fmt.Println("GetRolesForUser: ", r)
	}

	fmt.Println()
	if ok, err := e.Enforce("user:ian", "dom:admin", "obj:news", "act:read"); err != nil {
		fmt.Println("Enforce err: ", err)
	} else {
		fmt.Println(ok)
	}

	// fmt.Printf("GetAllActions: %#v\n\n", e.GetAllActions())

	// fmt.Println(e.AddRoleForUser("user:vancer", "role:organiser"))

	// if err := e.SavePolicy(); err != nil {
	// 	fmt.Println(333, err)
	// }

	// if r, err := e.GetUsersForRole("role:root"); err != nil {
	// 	fmt.Println(222, err)
	// } else {
	// 	fmt.Println("role:root: ", r)
	// }
	// if r, err := e.GetUsersForRole("role:admin"); err != nil {
	// 	fmt.Println(222, err)
	// } else {
	// 	fmt.Println("role:admin: ", r)
	// }
	// if r, err := e.GetUsersForRole("role:admin_member"); err != nil {
	// 	fmt.Println(222, err)
	// } else {
	// 	fmt.Println("role:admin_member: ", r)
	// }
	// if r, err := e.GetUsersForRole("role:organiser"); err != nil {
	// 	fmt.Println(222, err)
	// } else {
	// 	fmt.Println("role:organiser: ", r)
	// }

	// if ok, err := e.EnforceSafe("role:admin", "obj:news", "act:create"); err != nil {
	// 	fmt.Println(222, err)
	// } else {
	// 	fmt.Println(111, ok)
	// }
	// if ok, err := e.EnforceSafe("role:admin_member", "obj:news", "act:create"); err != nil {
	// 	fmt.Println(222, err)
	// } else {
	// 	fmt.Println(111, ok)
	// }
	// if ok, err := e.EnforceSafe("user:ian", "obj:account_admin_member", "act:create"); err != nil {
	// 	fmt.Println(222, err)
	// } else {
	// 	fmt.Println(111, ok)
	// }

}
