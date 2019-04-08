#!/bin/sh

go test -kubeconfig $HOME/.kube/config \
        -shootName "shoot" \
        -shootNamespace "garden-i355448" \
        -ginkgo.v \
        -ginkgo.progress \
#        -ginkgo.focus="Cloud-controller-manager"
