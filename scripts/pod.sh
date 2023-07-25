kubectl=${1}
k8sconfig=${2}
namespace=${3}
svc=${4}
port=${5}
alias k='$kubectl --kubeconfig $k8sconfig'
alias aprint_1="""awk '{print \$1}'"""
alias pod="""k -n $namespace get pods | grep $svc | aprint_1"""
pod
