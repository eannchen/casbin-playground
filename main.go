package main

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/constant"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	"github.com/pkg/errors"
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

func getAllObjects() []string {
	return []string{
		"obj:account",
		"obj:location",
		"obj:organiser",
		"obj:period",
		"obj:exhibition",
		"obj:news_tag",
		"obj:news",
		"obj:request_form",
	}
}

func getAllTrimmedObjects() []string {
	return []string{
		"account",
		"location",
		"organiser",
		"period",
		"exhibition",
		"news_tag",
		"news",
		"request_form",
	}
}

func getAllActions() []string {
	return []string{
		"act:read",
		"act:create",
		"act:update",
		"act:delete",
		"act:create_limited",
		"act:update_limited",
		"act:delete_limited",
	}
}

func getAllTrimmedActions() []string {
	return []string{
		"read",
		"create",
		"update",
		"delete",
		"create_limited",
		"update_limited",
		"delete_limited",
	}
}

const (
	UserPrefix       = "user:"
	RolePrefix       = "role:"
	DomPrefix        = "dom:"
	ObjPrefix        = "obj:"
	ActPrefix        = "act:"
	RolePrefixFormat = "role:%s:%d"
	RootRole         = RolePrefix + DivisionRoleNameRoot + ":0"
	CompanyDom       = DomPrefix + DivisionNameCompany
)

func main() {
	e, err := casbin.NewEnforcer("model_my.conf")
	if err != nil {
		log.Fatalf("casbin.NewEnforcer: %v", err)
	}
	e.SetFieldIndex("p", constant.SubjectIndex, 0)
	e.SetFieldIndex("p", constant.DomainIndex, 1)
	e.SetFieldIndex("p", constant.ObjectIndex, 2)

	adapter := fileadapter.NewAdapter("policy_my.csv")
	e.SetAdapter(adapter)

	if err := e.LoadPolicy(); err != nil {
		log.Fatalf("LoadPolicy: %v", err)
	}

	ctx := context.Background()

	if _, err := ListUsersPermission(ctx, e); err != nil {
		log.Fatalf("ListUsersPermission: %v", err)
	}
	ListDivisionsPermission(ctx, e)
}

func ListUsersPermission(ctx context.Context, e *casbin.Enforcer) ([]User, error) {
	users := mockListUsersFromDB()

	for i, user := range users {
		mUserPermissions := make(map[string][]Action)

		for _, divisionRole := range user.DivisionRoles {
			user := UserPrefix + user.Name
			dom := DomPrefix + string(divisionRole.Division.Name)

			rolePermissions, err := getUserPermissionsFromPolicy(ctx, e, user, dom)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("getUserPermissionsFromPolicy(ctx, e, %s, %s)", user, dom))
			}

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
	return users, nil
}

func mergeActions(existingActions, newActions []Action) []Action {
	mergedMap := make(map[string]Action)

	// Populate mergedMap with existingActions
	for _, existingAction := range existingActions {
		mergedMap[existingAction.Name] = existingAction
	}

	// Update mergedMap with newActions
	for _, newAction := range newActions {
		if existingAction, exists := mergedMap[newAction.Name]; exists && newAction.Status {
			existingAction.Status = true
			mergedMap[newAction.Name] = existingAction
		} else {
			mergedMap[newAction.Name] = newAction
		}
	}

	// Convert map values to slice
	mergedActions := make([]Action, 0, len(mergedMap))
	for _, action := range mergedMap {
		mergedActions = append(mergedActions, action)
	}

	return mergedActions
}

func getUserPermissionsFromPolicy(ctx context.Context, e *casbin.Enforcer, user string, dom string) ([]Permission, error) {

	ok, err := e.HasRoleForUser(user, string(RootRole), dom)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("HasRoleForUser(%s, %s, %s)", user, RootRole, dom))
	}
	if ok {
		return allAllowPermissions(), nil
	}

	mPermissions := generatePermissionsMapping()
	policy, err := e.GetImplicitPermissionsForUser(user, dom)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("GetImplicitPermissionsForUser(%s, %s)", user, dom))
	}
	for _, p := range policy {
		obj, act := p[2], p[3]
		mPermissions[obj][act] = true
	}

	return buildPermissionsFromMapping(mPermissions), nil
}

func ListDivisionsPermission(ctx context.Context, e *casbin.Enforcer) []Division {
	divisions := mockListDivisionsFromDB()

	for i, division := range divisions {
		for j, divisionRole := range division.DivisionRoles {
			role := fmt.Sprintf(RolePrefixFormat, divisionRole.Name, divisionRole.Level)
			// role := RolePrefix + string(divisionRole.Name) + ":" + fmt.Sprint(divisionRole.Level)
			dom := DomPrefix + string(division.Name)

			permissions := getRolePermissionsFromPolicy(ctx, e, role, dom)
			divisions[i].DivisionRoles[j].Permissions = permissions
		}
	}

	return divisions
}

func getRolePermissionsFromPolicy(ctx context.Context, e *casbin.Enforcer, role string, dom string) []Permission {

	if strings.EqualFold(role, string(RootRole)) &&
		strings.EqualFold(dom, string(CompanyDom)) {
		return allAllowPermissions()
	}

	mPermissions := generatePermissionsMapping()
	policy := e.GetFilteredPolicy(0, role, dom)
	for _, p := range policy {
		obj, act := p[2], p[3]
		mPermissions[obj][act] = true
	}

	return buildPermissionsFromMapping(mPermissions)
}

func generatePermissionsMapping() map[string]map[string]bool {
	mPermissions := make(map[string]map[string]bool)
	for _, obj := range getAllObjects() {
		mPermissions[obj] = make(map[string]bool)
		for _, act := range getAllActions() {
			mPermissions[obj][act] = false
		}
	}
	return mPermissions
}

func buildPermissionsFromMapping(mPermissions map[string]map[string]bool) []Permission {
	var permissions []Permission

	for obj, mAct := range mPermissions {
		var actions []Action
		for act, eft := range mAct {
			actions = append(actions, Action{
				Name:   strings.TrimPrefix(act, ActPrefix),
				Status: eft,
			})
		}
		permissions = append(permissions, Permission{
			Name:    strings.TrimPrefix(obj, ObjPrefix),
			Actions: actions,
		})
	}

	return permissions
}

func allAllowPermissions() []Permission {
	// Preallocates the slice based on the number of objects for efficiency.
	permissions := make([]Permission, 0, len(getAllTrimmedObjects()))

	for _, obj := range getAllTrimmedObjects() {
		permission := Permission{Name: obj}
		for _, act := range getAllTrimmedActions() {
			permission.Actions = append(permission.Actions, Action{
				Name:   act,
				Status: true,
			})
		}
		permissions = append(permissions, permission)
	}
	return permissions
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
