#!/bin/sh

ginkgo -progress -v -noColor -nodes=25 --focus=aws . -- \
        -kubeconfig $HOME/.kube/config \
        -shootName "shoot" \
        -shootNamespace "garden-i355448"
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