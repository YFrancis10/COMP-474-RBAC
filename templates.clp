(deftemplate user
   (slot id (type SYMBOL)))

(deftemplate role
   (slot name (type SYMBOL))
   (slot privileged (type SYMBOL) (allowed-symbols yes no)))

(deftemplate user-role
   (slot user (type SYMBOL))
   (slot role (type SYMBOL)))

(deftemplate permission
   (slot role (type SYMBOL))
   (slot action (type SYMBOL))
   (slot resource (type SYMBOL)))

(deftemplate resource
   (slot id (type SYMBOL))
   (slot type (type SYMBOL))
   (slot owner (type SYMBOL))
   (slot state (type SYMBOL)))

(deftemplate access-request
   (slot user (type SYMBOL))
   (slot action (type SYMBOL))
   (slot resource (type SYMBOL)))

(deftemplate decision
   (slot result (type SYMBOL) (allowed-symbols grant deny))
   (slot reason (type STRING)))

(deftemplate access-log
   (slot user (type SYMBOL))
   (slot action (type SYMBOL))
   (slot resource (type SYMBOL))
   (slot result (type SYMBOL))
   (slot rule-name (type STRING)))

(deftemplate ownership-required
   (slot action (type SYMBOL)))

(deftemplate privilege-required
   (slot action (type SYMBOL)))