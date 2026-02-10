(deffacts startup-facts
   ;; Users
   (user (id alice))
   (user (id bob))

   ;; Roles
   (role (name admin) (privileged yes))
   (role (name editor) (privileged no))
   (role (name viewer) (privileged no))

   ;; User-role assignments
   (user-role (user alice) (role admin))
   (user-role (user bob) (role editor))

   ;; Permissions
   (permission (role admin) (action delete) (resource document))
   (permission (role editor) (action edit) (resource document))
   (permission (role viewer) (action view) (resource document))

   ;; Resources
   (resource (id doc1) (type document) (owner alice) (state active))

   ;; Access request
   (access-request (user bob) (action edit) (resource doc1))
)