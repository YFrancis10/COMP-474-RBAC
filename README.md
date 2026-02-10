Load in following order:

(load "templates.clp")
(load "facts.clp")
(load "rules.clp")
(batch "test.clp")

For debugging include:

(watch rules)
(watch facts)