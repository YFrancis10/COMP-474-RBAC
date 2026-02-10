;; Test 1: Valid access — bob edits active doc1
(printout t crlf "=== TEST 1: Bob edits active doc1 (expect GRANT) ===" crlf)
(reset)
(assert (access-request (user bob) (action edit) (resource doc1)))
(run)

;; Test 2: Unauthorized action — bob deletes doc1
(printout t crlf "=== TEST 2: Bob deletes doc1 (expect DENY) ===" crlf)
(reset)
(assert (access-request (user bob) (action delete) (resource doc1)))
(run)

;; Test 3: Unknown user — charlie
(printout t crlf "=== TEST 3: Unknown user charlie (expect DENY) ===" crlf)
(reset)
(assert (user-role (user charlie) (role viewer)))
(assert (access-request (user charlie) (action view) (resource doc1)))
(run)

;; Test 4: No role — dave
(printout t crlf "=== TEST 4: Dave has no role (expect DENY) ===" crlf)
(reset)
(assert (user (id dave)))
(assert (access-request (user dave) (action view) (resource doc1)))
(run)

;; Test 5: Archived resource
(printout t crlf "=== TEST 5: Bob edits archived doc2 (expect DENY) ===" crlf)
(reset)
(assert (resource (id doc2) (type document) (owner alice) (state archived)))
(assert (access-request (user bob) (action edit) (resource doc2)))
(run)

;; Test 6: Unknown resource
(printout t crlf "=== TEST 6: Bob edits nonexistent doc99 (expect DENY) ===" crlf)
(reset)
(assert (access-request (user bob) (action edit) (resource doc99)))
(run)
