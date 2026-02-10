;; Rule 1: Deny if user has no role
(defrule deny-no-role
   (declare (salience 90))
   (access-request (user ?u))
   (not (user-role (user ?u)))
   =>
   (assert (decision (result deny) (reason "User has no assigned role"))))

;; Rule 2: Deny if no role permits the action
(defrule deny-no-permission
   (declare (salience 40))
   (access-request (user ?u) (action ?a) (resource ?r))
   (resource (id ?r) (type ?type))
   (not (and (user-role (user ?u) (role ?role))
             (permission (role ?role) (action ?a) (resource ?type))))
   =>
   (assert (decision (result deny) (reason "No assigned role permits this action"))))

;; Rule 3: Grant if role permits action on resource type
(defrule grant-permitted-action
   (declare (salience 50))
   (access-request (user ?u) (action ?a) (resource ?r))
   (user-role (user ?u) (role ?role))
   (permission (role ?role) (action ?a) (resource ?type))
   (resource (id ?r) (type ?type) (state active))
   =>
   (assert (decision (result grant) (reason "Role permits action on resource"))))

;;; Ownership Constraint Rules (4-5)

;; Rule 4: Deny if action requires ownership and user is not owner
(defrule deny-not-owner
   (declare (salience 70))
   (access-request (user ?u) (action ?a) (resource ?r))
   (ownership-required (action ?a))
   (resource (id ?r) (owner ?owner))
   (test (neq ?u ?owner))
   =>
   (assert (decision (result deny) (reason "Action requires ownership; user is not the owner"))))

;; Rule 5: Grant if user is owner and role allows action
(defrule grant-owner-action
   (declare (salience 60))
   (access-request (user ?u) (action ?a) (resource ?r))
   (ownership-required (action ?a))
   (resource (id ?r) (type ?type) (owner ?u) (state active))
   (user-role (user ?u) (role ?role))
   (permission (role ?role) (action ?a) (resource ?type))
   =>
   (assert (decision (result grant) (reason "Owner with permitted role"))))

;;; Privilege Constraint Rules (6-7)

;; Rule 6: Deny if action requires privilege and user lacks it
(defrule deny-no-privilege
   (declare (salience 70))
   (access-request (user ?u) (action ?a) (resource ?r))
   (privilege-required (action ?a))
   (user-role (user ?u) (role ?role))
   (role (name ?role) (privileged no))
   (not (and (user-role (user ?u) (role ?prole))
             (role (name ?prole) (privileged yes))))
   =>
   (assert (decision (result deny) (reason "Action requires privileged role"))))

;; Rule 7: Grant if user has privileged role that permits action
(defrule grant-privileged-action
   (declare (salience 60))
   (access-request (user ?u) (action ?a) (resource ?r))
   (privilege-required (action ?a))
   (user-role (user ?u) (role ?role))
   (role (name ?role) (privileged yes))
   (permission (role ?role) (action ?a) (resource ?type))
   (resource (id ?r) (type ?type) (state active))
   =>
   (assert (decision (result grant) (reason "Privileged role permits action"))))

;;; Resource State Rules (8-9)

;; Rule 8: Deny modification on archived resources
(defrule deny-archived-modification
   (declare (salience 80))
   (access-request (action ?a&edit|delete) (resource ?r))
   (resource (id ?r) (state archived))
   =>
   (assert (decision (result deny) (reason "Cannot modify archived resource"))))

;; Rule 9: Allow modification on active resources (handled by grant rules above via state active check)
;; This rule exists as explicit documentation
(defrule allow-active-modification
   (declare (salience 50))
   (access-request (user ?u) (action ?a&edit|delete) (resource ?r))
   (resource (id ?r) (type ?type) (state active))
   (user-role (user ?u) (role ?role))
   (permission (role ?role) (action ?a) (resource ?type))
   =>
   (assert (decision (result grant) (reason "Active resource; role permits modification"))))

;;; Multi-Role Reasoning (10-11)

;; Rule 10: Any matching role is sufficient (covered by grant rules using any binding)

;; Rule 11: Deny on role conflict — grant and deny both exist
(defrule resolve-conflict-deny-wins
   (declare (salience 95))
   ?g <- (decision (result grant))
   (decision (result deny))
   =>
   (retract ?g))

;;; Safety Rules (12-13)

;; Rule 12: Deny if critical facts missing (no user record)
(defrule deny-missing-user
   (declare (salience 100))
   (access-request (user ?u))
   (not (user (id ?u)))
   =>
   (assert (decision (result deny) (reason "Unknown user"))))

;; Rule 13: Deny if resource in request doesn't exist
(defrule deny-missing-resource
   (declare (salience 100))
   (access-request (resource ?r))
   (not (resource (id ?r)))
   =>
   (assert (decision (result deny) (reason "Unknown resource"))))

;;; Default Rule (14)

;; Rule 14: Deny by default — lowest priority
(defrule deny-by-default
   (declare (salience -100))
   (access-request)
   (not (decision))
   =>
   (assert (decision (result deny) (reason "Default deny: no rule explicitly granted access"))))

;;; Explanation Rules (15-16)

;; Rule 15: Explain denial due to missing permission
(defrule explain-deny-no-permission
   (declare (salience 30))
   (decision (result deny) (reason ?r&"No assigned role permits this action"))
   =>
   (printout t "EXPLANATION: Access denied — " ?r crlf))

;; Rule 16: Explain denial due to ownership
(defrule explain-deny-ownership
   (declare (salience 30))
   (decision (result deny) (reason ?r&"Action requires ownership; user is not the owner"))
   =>
   (printout t "EXPLANATION: Access denied — " ?r crlf))

;;; Consistency Rules (17-18)

;; Rule 17: Warn if privileged role has no permissions
(defrule warn-privileged-no-permissions
   (declare (salience 100))
   (role (name ?role) (privileged yes))
   (not (permission (role ?role)))
   =>
   (printout t "WARNING: Privileged role '" ?role "' has no permissions defined." crlf))

;; Rule 18: Deny if permission references unknown resource type
(defrule deny-unknown-resource-type
   (declare (salience 100))
   (access-request (user ?u) (action ?a) (resource ?r))
   (user-role (user ?u) (role ?role))
   (permission (role ?role) (action ?a) (resource ?type))
   (not (resource (type ?type)))
   =>
   (assert (decision (result deny) (reason "Permission references unknown resource type"))))

;;; Audit Rules (19-20)

;; Rule 19: Log granted access
(defrule audit-grant
   (declare (salience 10))
   (access-request (user ?u) (action ?a) (resource ?r))
   (decision (result grant) (reason ?reason))
   =>
   (assert (access-log (user ?u) (action ?a) (resource ?r)
                       (result grant) (rule-name ?reason)))
   (printout t "AUDIT: GRANT — User=" ?u " Action=" ?a " Resource=" ?r
               " Reason=" ?reason crlf))

;; Rule 20: Log denied access
(defrule audit-deny
   (declare (salience 10))
   (access-request (user ?u) (action ?a) (resource ?r))
   (decision (result deny) (reason ?reason))
   =>
   (assert (access-log (user ?u) (action ?a) (resource ?r)
                       (result deny) (rule-name ?reason)))
   (printout t "AUDIT: DENY — User=" ?u " Action=" ?a " Resource=" ?r
               " Reason=" ?reason crlf))