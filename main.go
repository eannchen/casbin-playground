package main

import (
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/constant"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
)

type User struct {
	Name          string         `json:"name"`
	DivisionRoles []DivisionRole `json:"divisionRoles"`
	Permissions   []Permission   `json:"permissions,omitempty"`
}

type DivisionName string

const (
	DivisionNameCompany DivisionName = "Company"
	DivisionNameGuest   DivisionName = "Guest"
)

type DivisionType string

const (
	DivisionTypeCompany  DivisionType = "company"
	DivisionTypeDivision DivisionType = "division"
	DivisionTypeGuest    DivisionType = "guest"
)

type Division struct {
	Name          DivisionName   `json:"name"`
	Type          DivisionType   `json:"type"`
	DivisionRoles []DivisionRole `json:"divisionRoles"`
}

type DivisionRoleName string

const (
	DivisionRoleNameRoot      DivisionRoleName = "root"
	DivisionRoleNameOrganiser DivisionRoleName = "organiser"
)

type DivisionRole struct {
	Division    *Division        `json:"division,omitempty"`
	Name        DivisionRoleName `json:"name"`
	Level       int              `json:"level"`
	Permissions []Permission     `json:"permissions,omitempty"`
}

type Permission struct {
	Name    string   `json:"name"`
	Actions []Action `json:"actions"`
}

type Action struct {
	Name   string `json:"name"`
	Status bool   `json:"status"`
}

var allObjects = []string{
	"obj:account",
	"obj:location",
	"obj:organiser",
	"obj:period",
	"obj:exhibition",
	"obj:news_tag",
	"obj:news",
	"obj:request_form",
}

var allActions = []string{
	"act:read",
	"act:create",
	"act:update",
	"act:delete",
	"act:create_limited",
	"act:update_limited",
	"act:delete_limited",
}

func main() {
	e, err := casbin.NewEnforcer("model_my.conf")
	if err != nil {
		fmt.Errorf("casbin.NewEnforcer", err)
	}
	e.SetFieldIndex("p", constant.SubjectIndex, 0)
	e.SetFieldIndex("p", constant.DomainIndex, 1)
	e.SetFieldIndex("p", constant.ObjectIndex, 2)

	adapter := fileadapter.NewAdapter("policy_my.csv")
	e.SetAdapter(adapter)

	if err := e.LoadPolicy(); err != nil {
		fmt.Errorf("LoadPolicy", err)
	}

	ListUsersPermission(e)
	ListDivisionsPermission(e)
}

func ListUsersPermission(e *casbin.Enforcer) []User {
	users := mockListUsersFromDB()

	for i, user := range users {
		mUserPermissions := make(map[string][]Action)

		for _, divisionRole := range user.DivisionRoles {
			user := "user:" + user.Name
			dom := "dom:" + string(divisionRole.Division.Name)

			rolePermissions := getUserPermissionsFromPolicy(e, user, dom)
			// users[i].DivisionRoles[j].Permissions = rolePermissions

			for _, permission := range rolePermissions {
				if existingActions, ok := mUserPermissions[permission.Name]; ok {
					// Merge actions if the permission already exists
					mUserPermissions[permission.Name] = mergeActions(existingActions, permission.Actions)
				} else {
					// Add the permission if it doesn't exist
					mUserPermissions[permission.Name] = permission.Actions
				}
			}
		}

		var userPermissions []Permission
		for name, actions := range mUserPermissions {
			userPermissions = append(userPermissions, Permission{
				Name:    name,
				Actions: actions,
			})
		}
		users[i].Permissions = userPermissions
	}
	return users
}

func mergeActions(existingActions []Action, newActions []Action) []Action {
	mergedActions := make([]Action, len(existingActions))

	for i, existingAction := range existingActions {
		for _, newAction := range newActions {
			if existingAction.Name == newAction.Name && newAction.Status {
				mergedActions[i] = newAction
				break
			} else {
				mergedActions[i] = existingAction
			}
		}
	}

	return mergedActions
}

func getUserPermissionsFromPolicy(e *casbin.Enforcer, user string, dom string) []Permission {

	if ok, _ := e.HasRoleForUser(user, "role:root:0", dom); ok {
		return allAllowPermissions()
	}

	mPermissions := make(map[string]map[string]bool)
	for _, obj := range allObjects {
		mPermissions[obj] = make(map[string]bool)
		for _, act := range allActions {
			mPermissions[obj][act] = false
		}
	}

	policy, _ := e.GetImplicitPermissionsForUser(user, dom)
	for _, p := range policy {
		obj, act := p[2], p[3]
		mPermissions[obj][act] = true
	}

	var permissions []Permission
	for obj, mAct := range mPermissions {
		var actions []Action
		for act, eft := range mAct {
			actions = append(actions, Action{
				Name:   strings.TrimPrefix(act, "act:"),
				Status: eft,
			})
		}
		permissions = append(permissions, Permission{
			Name:    strings.TrimPrefix(obj, "obj:"),
			Actions: actions,
		})
	}
	return permissions
}

func ListDivisionsPermission(e *casbin.Enforcer) []Division {
	divisions := mockListDivisionsFromDB()

	for i, division := range divisions {
		for j, divisionRole := range division.DivisionRoles {
			role := "role:" + string(divisionRole.Name) + ":" + fmt.Sprint(divisionRole.Level)
			dom := "dom:" + string(division.Name)

			permissions := getRolePermissionsFromPolicy(e, role, dom)
			divisions[i].DivisionRoles[j].Permissions = permissions
		}
	}

	return divisions
}

func getRolePermissionsFromPolicy(e *casbin.Enforcer, role string, dom string) []Permission {

	if strings.EqualFold(role, string("role:"+DivisionRoleNameRoot+":0")) &&
		strings.EqualFold(dom, string("dom:"+DivisionNameCompany)) {
		return allAllowPermissions()
	}

	mPermissions := make(map[string]map[string]bool)
	for _, obj := range allObjects {
		mPermissions[obj] = make(map[string]bool)
		for _, act := range allActions {
			mPermissions[obj][act] = false
		}
	}
	policy := e.GetFilteredPolicy(0, role, dom)
	for _, p := range policy {
		obj, act := p[2], p[3]
		mPermissions[obj][act] = true
	}

	var permissions []Permission
	for obj, mAct := range mPermissions {
		var actions []Action
		for act, eft := range mAct {
			actions = append(actions, Action{
				Name:   strings.TrimPrefix(act, "act:"),
				Status: eft,
			})
		}
		permissions = append(permissions, Permission{
			Name:    strings.TrimPrefix(obj, "obj:"),
			Actions: actions,
		})
	}
	return permissions
}

func allAllowPermissions() (permissions []Permission) {
	for _, obj := range allObjects {
		var permission Permission
		permission.Name = strings.TrimPrefix(obj, "obj:")
		for _, act := range allActions {
			permission.Actions = append(permission.Actions, Action{
				Name:   strings.TrimPrefix(act, "act:"),
				Status: true,
			})
		}
		permissions = append(permissions, permission)
	}
	return
}

func mockListUsersFromDB() []User {
	return []User{
		User{
			Name: "jason",
			DivisionRoles: []DivisionRole{
				DivisionRole{
					Division: &Division{
						Name: DivisionNameCompany,
						Type: DivisionTypeCompany,
					},
					Name:  DivisionRoleNameRoot,
					Level: 0,
				},
			},
		},
		User{
			Name: "sonnie",
			DivisionRoles: []DivisionRole{
				DivisionRole{
					Division: &Division{
						Name: DivisionNameCompany,
						Type: DivisionTypeCompany,
					},
					Name:  DivisionRoleName("admin"),
					Level: 1,
				},
			},
		},
		User{
			Name: "sonnie2",
			DivisionRoles: []DivisionRole{
				DivisionRole{
					Division: &Division{
						Name: DivisionNameCompany,
						Type: DivisionTypeCompany,
					},
					Name:  DivisionRoleName("admin_member"),
					Level: 2,
				},
			},
		},
		User{
			Name: "ian",
			DivisionRoles: []DivisionRole{
				DivisionRole{
					Division: &Division{
						Name: DivisionNameCompany,
						Type: DivisionTypeCompany,
					},
					Name:  DivisionRoleName("admin"),
					Level: 1,
				},
				DivisionRole{
					Division: &Division{
						Name: DivisionName("marketing"),
						Type: DivisionTypeDivision,
					},
					Name:  DivisionRoleName("admin"),
					Level: 0,
				},
			},
		},
		User{
			Name: "ian2",
			DivisionRoles: []DivisionRole{
				DivisionRole{
					Division: &Division{
						Name: DivisionName("marketing"),
						Type: DivisionTypeDivision,
					},
					Name:  DivisionRoleName("admin_leader"),
					Level: 1,
				},
			},
		},
		User{
			Name: "vancer",
			DivisionRoles: []DivisionRole{
				DivisionRole{
					Division: &Division{
						Name: DivisionNameGuest,
						Type: DivisionTypeGuest,
					},
					Name:  DivisionRoleNameOrganiser,
					Level: 0,
				},
			},
		},
	}
}

func mockListDivisionsFromDB() []Division {
	return []Division{
		Division{
			Name: DivisionNameCompany,
			Type: DivisionTypeCompany,
			DivisionRoles: []DivisionRole{
				DivisionRole{
					Name:  DivisionRoleNameRoot,
					Level: 0,
				},
				DivisionRole{
					Name:  DivisionRoleName("admin"),
					Level: 1,
				},
				DivisionRole{
					Name:  DivisionRoleName("admin_member"),
					Level: 2,
				},
			},
		},
		Division{
			Name: "marketing",
			Type: DivisionTypeDivision,
			DivisionRoles: []DivisionRole{
				DivisionRole{
					Name:  DivisionRoleName("admin"),
					Level: 0,
				},
				DivisionRole{
					Name:  DivisionRoleName("admin_leader"),
					Level: 1,
				},
			},
		},
		Division{
			Name: DivisionNameGuest,
			Type: DivisionTypeGuest,
			DivisionRoles: []DivisionRole{
				DivisionRole{
					Name:  DivisionRoleNameOrganiser,
					Level: 0,
				},
			},
		},
	}
}
