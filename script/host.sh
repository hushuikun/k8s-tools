kubectl=${1}
k8sconfig=${2}
namespace=${3}
alias k='$kubectl --kubeconfig $k8sconfig'
alias aprint_1="""awk 'NR != 1 {print \$3 \"\t\" \$1}'"""
alias host='k -n $namespace get services | aprint_1'
host
