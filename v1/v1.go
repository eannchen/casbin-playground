package v1

import (
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2"
)

type User struct {
	Name          string         `json:"name"`
	DivisionRoles []DivisionRole `json:"divisionRoles"`
	Permissions   []Permission   `json:"permissions"`
}

type DivisionType string

const (
	DivisionTypeCompany  DivisionType = "company"
	DivisionTypeDivision DivisionType = "division"
	DivisionTypeGuest    DivisionType = "guest"
)

type Division struct {
	Name          string         `json:"name"`
	Type          DivisionType   `json:"type"`
	DivisionRoles []DivisionRole `json:"divisionRoles"`
}

type DivisionRole struct {
	Division    *Division    `json:"division,omitempty"`
	Name        string       `json:"name"`
	Level       int          `json:"level"`
	Permissions []Permission `json:"permissions"`
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
var actionExpansionMapping = map[string][]string{
	"act:all": []string{
		"act:read", "act:create", "act:update", "act:delete", "act:create_limited", "act:update_limited", "act:delete_limited",
	},
	"act:all_limited": []string{
		"act:read", "act:create_limited", "act:update_limited", "act:delete_limited",
	},
	"act:create": {"act:create", "act:create_limited"},
	"act:update": {"act:update", "act:update_limited"},
	"act:delete": {"act:delete", "act:delete_limited"},
}

var eftMapping = map[string]bool{
	"allow": true,
	"deny":  false,
}

func ListDivisionsPermission(e *casbin.Enforcer) []Division {
	divisions := mockListDivisionsFromDB()

	domMapping := completeRolesPolicy(e)

	for i, division := range divisions {
		dom := "dom:" + string(division.Name)
		for j, divisionRole := range division.DivisionRoles {
			var permissions []Permission
			role := "role:" + string(divisionRole.Name) + ":" + fmt.Sprint(divisionRole.Level)
			objectToActions := domMapping[dom][role]
			for obj, acts := range objectToActions {
				var permission Permission
				permission.Name = strings.TrimPrefix(obj, "obj:")
				for _, actNEft := range acts {
					aActNEft := strings.Split(actNEft, ",")
					act, eft := strings.TrimSpace(aActNEft[0]), eftMapping[strings.TrimSpace(aActNEft[1])]
					permission.Actions = append(permission.Actions, Action{
						Name:   act,
						Status: eft,
					})
				}
				permissions = append(permissions, permission)
			}
			divisions[i].DivisionRoles[j].Permissions = permissions
		}
	}

	return divisions
}

func ListDivisionsRolesPermission(e *casbin.Enforcer) []DivisionRole {
	divisionRoles := mockListDivisionRolesFromDB()

	domMapping := completeRolesPolicy(e)

	for i, divisionRole := range divisionRoles {
		var permissions []Permission
		dom := "dom:" + string(divisionRole.Division.Name)
		role := "role:" + string(divisionRole.Name) + ":" + fmt.Sprint(divisionRole.Level)

		objectToActions := domMapping[dom][role]

		for obj, acts := range objectToActions {
			var permission Permission
			permission.Name = strings.TrimPrefix(obj, "obj:")
			for _, actNEft := range acts {
				aActNEft := strings.Split(actNEft, ",")
				act, eft := strings.TrimSpace(aActNEft[0]), eftMapping[strings.TrimSpace(aActNEft[1])]
				permission.Actions = append(permission.Actions, Action{
					Name:   act,
					Status: eft,
				})
			}
			permissions = append(permissions, permission)
		}

		divisionRoles[i].Permissions = permissions
	}

	return divisionRoles
}

func completeRolesPolicy(e *casbin.Enforcer) map[string]map[string]map[string][]string {

	// map[dom]map[role]map[obj][]string of "act:effect"
	DomMapping := make(map[string]map[string]map[string][]string)

	policy := e.GetPolicy()

	for _, p := range policy {
		if !strings.HasPrefix(p[0], "role:") {
			continue
		}
		sub, dom, obj, act, eft := p[0], p[1], p[2], p[3], p[4]

		expandedActions := expandActions(act)

		if _, ok := DomMapping[dom]; !ok {
			DomMapping[dom] = make(map[string]map[string][]string)
		}

		if _, ok := DomMapping[dom][sub]; !ok {
			DomMapping[dom][sub] = make(map[string][]string)
		}

		for _, act := range expandedActions {
			DomMapping[dom][sub][obj] = append(DomMapping[dom][sub][obj], fmt.Sprintf("%s, %s", act, eft))
		}
	}

	// Handle implicit denials
	for dom, roleMapping := range DomMapping {
		for role, objActions := range roleMapping {
			for _, obj := range allObjects {
				if _, ok := objActions[obj]; !ok {
					// Deny all actions for this object
					objActions[obj] = make([]string, 0, len(allActions)) // Pre-allocate space for performance
					for _, act := range allActions {
						objActions[obj] = append(objActions[obj], fmt.Sprintf("%s, deny", act))
					}
				} else {
					// Ensure all actions are explicitly included, even with "deny" effects
					for _, act := range allActions {
						found := false
						for _, existingAct := range objActions[obj] {
							if strings.HasPrefix(existingAct, fmt.Sprintf("%s,", act)) {
								found = true
								break
							}
						}
						if !found {
							objActions[obj] = append(objActions[obj], fmt.Sprintf("%s, deny", act))
						}
					}
				}
			}
			roleMapping[role] = objActions
		}
		DomMapping[dom] = roleMapping
	}

	return DomMapping
}

func expandActions(action string) []string {
	if expandedActions, ok := actionExpansionMapping[action]; ok {
		return expandedActions
	}
	return []string{action}
}

func mockListUsersFromDB() []User {
	return []User{
		User{
			Name: "jason",
			DivisionRoles: []DivisionRole{
				DivisionRole{
					Division: &Division{
						Name: "company",
						Type: DivisionTypeCompany,
					},
					Name:  "root",
					Level: 0,
				},
			},
		},
		User{
			Name: "sonnie",
			DivisionRoles: []DivisionRole{
				DivisionRole{
					Division: &Division{
						Name: "company",
						Type: DivisionTypeCompany,
					},
					Name:  "admin",
					Level: 1,
				},
			},
		},
		User{
			Name: "ian",
			DivisionRoles: []DivisionRole{
				DivisionRole{
					Division: &Division{
						Name: "marketing",
						Type: DivisionTypeDivision,
					},
					Name:  "admin",
					Level: 0,
				},
			},
		},
		User{
			Name: "vancer",
			DivisionRoles: []DivisionRole{
				DivisionRole{
					Division: &Division{
						Name: "guest",
						Type: DivisionTypeGuest,
					},
					Name:  "guest",
					Level: 0,
				},
			},
		},
	}
}

func mockListDivisionsFromDB() []Division {
	return []Division{
		Division{
			Name: "company",
			Type: DivisionTypeCompany,
			DivisionRoles: []DivisionRole{
				DivisionRole{
					Name:  "admin",
					Level: 1,
				},
				DivisionRole{
					Name:  "admin_member",
					Level: 2,
				},
			},
		},
		Division{
			Name: "marketing",
			Type: DivisionTypeDivision,
			DivisionRoles: []DivisionRole{
				DivisionRole{
					Name:  "admin",
					Level: 0,
				},
			},
		},
		Division{
			Name: "guest",
			Type: DivisionTypeGuest,
			DivisionRoles: []DivisionRole{
				DivisionRole{
					Name:  "guest",
					Level: 0,
				},
			},
		},
	}
}

func mockListDivisionRolesFromDB() []DivisionRole {
	return []DivisionRole{
		DivisionRole{
			Division: &Division{
				Name: "company",
				Type: DivisionTypeCompany,
			},
			Name:  "admin",
			Level: 1,
		},
		DivisionRole{
			Division: &Division{
				Name: "company",
				Type: DivisionTypeCompany,
			},
			Name:  "admin_member",
			Level: 2,
		},
		DivisionRole{
			Division: &Division{
				Name: "marketing",
				Type: DivisionTypeDivision,
			},
			Name:  "admin",
			Level: 0,
		},
		DivisionRole{
			Division: &Division{
				Name: "guest",
				Type: DivisionTypeGuest,
			},
			Name:  "guest",
			Level: 0,
		},
	}
}
