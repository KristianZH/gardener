#!/bin/sh

ginkgo --progress -v --noColor -nodes=25 --randomizeAllSpecs --randomizeSuites --failOnPending --trace --race alicloud -- \
        -kubeconfig $HOME/.kube/config \
        -shootName "netpolicy" \
        -shootNamespace "garden-i068969" \
        -cleanup=false
# go test -kubeconfig $HOME/.kube/config \
#         -shootName "shoot" \
#         -shootNamespace "garden-i355448" \
#         -ginkgo.v \
#         -ginkgo.progress \
#         -ginkgo.parallel.node 5 \
#         -ginkgo.parallel.total 5
# #        -ginkgo.focus="Cloud-controller-manager"


# ginkgo -progress -v --focus=aws . -- \
#         -kubeconfig $HOME/.kube/config \
#         -shootName "shoot" \
#         -shootNamespace "garden-i355448"
