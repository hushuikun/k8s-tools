import os
import time
import signal
import threading
import subprocess

from flask import Flask, request, render_template
from python_hosts import Hosts, HostsEntry

from utils import is_resolvable, is_port_in_use
from models import Config, Telepresence, HostConfig, Host, Portforward


base_dir = os.path.dirname(os.path.abspath(__file__))


def _telepresence_with_retry():
    config = Config.select()[0]
    sudo_pwd_cmd = (f"echo {config.sudo_password} | sudo -S"
                    if config.sudo_password else "")
    telepresence_path = config.telepresence_path
    os.system(f"{sudo_pwd_cmd} {telepresence_path} quit -ur")
    thread_file_path = None
    while True:
        telepresence = Telepresence.select()[0]
        k8s_file_path = os.path.join(
            config.k8s_config_path, telepresence.k8s_file)
        if (not is_resolvable("traffic-manager.ambassador")
                or thread_file_path != k8s_file_path):
            os.system((f"{sudo_pwd_cmd} {telepresence_path} quit -ur && "
                       f"{sudo_pwd_cmd} {telepresence_path} connect "
                       f"--kubeconfig {k8s_file_path}"))
            if is_resolvable("traffic-manager.ambassador"):
                telepresence.state = "connected"
                telepresence.save()
                thread_file_path = k8s_file_path
                print("******telepresence connect success******")
        time.sleep(5)

def telepresence_with_retry(k8s_file, restart=False):
    try:
        telepresence = Telepresence.select()[0]
    except IndexError:
        telepresence = None
    if telepresence:
        if restart is False:
            if k8s_file != telepresence.k8s_file:
                telepresence.k8s_file = k8s_file
                telepresence.state = "connecting"
                telepresence.save()
                return
        else:
            telepresence.k8s_file = k8s_file
            telepresence.state = "connecting"
            telepresence.save()
    else:
        Telepresence(k8s_file=k8s_file, state="connecting").save()
    thread = threading.Thread(target=_telepresence_with_retry)
    thread.start()
    return

def _portforward_with_retry(k8s_file, namespace, svc, port):
    k = f"{k8s_file}###{namespace}###{svc}###{port}"
    while True:
        try:
            config = Config.select()[0]
            portforward = Portforward.get(key=k)
        except Exception:
            break
        k8s_file_path = os.path.join(config.k8s_config_path, k8s_file)
        kubectl_path = config.kubectl_path
        script_path = os.path.join(base_dir, "script/pod.sh")
        pods = os.popen(
            f"sh {script_path} {kubectl_path} {k8s_file_path} {namespace} {svc} {port}"
        ).read()
        pods = [i.split("\t")[0] for i in pods.split("\n") if i]
        if pods:
            process = subprocess.Popen(
                [kubectl_path, '--kubeconfig', k8s_file_path,
                 '-n', namespace, 'port-forward', pods[0], port]
            )
            # 获取子进程的进程ID
            portforward.subprocess_id = process.pid
            portforward.save()
            print("Portforward子进程的进程ID:", process.pid)
            process.communicate()
        else:
            break

def portforward_with_retry(k8s_file, namespace, svc, port):
    thread = threading.Thread(
        target=_portforward_with_retry, args=(k8s_file, namespace, svc, port))
    thread.start()


class App(Flask):
    def __init__(self, *args, **kwargs):
        Config.create_table()
        Telepresence.create_table()
        HostConfig.create_table()
        Host.create_table()
        Portforward.create_table()
        super().__init__(*args, **kwargs)
        self.restart()

    def restart(self):
        # host重写
        if Host.select():
            hosts_file = Hosts(path='/etc/hosts')
            for host in Host.select():
                # 先删除同名hosts
                hosts_file.remove_all_matching(name=host.name)
                hosts_file.write()
                # 再添加host
                if host.ip != "None":
                    new_entry = HostsEntry(
                        entry_type='ipv4', address=host.ip, names=[host.name])
                    hosts_file.add([new_entry])
                hosts_file.write()
            print("******rewrite hosts success******")
        # port-forward重启
        if Portforward.select():
            for portforward in Portforward.select():
                k8s_file, namespace, svc, port = portforward.key.split("###")
                if portforward.subprocess_id:
                    try:
                        os.kill(int(portforward.subprocess_id), signal.SIGKILL)
                    except Exception:
                        pass
                portforward_with_retry(k8s_file, namespace, svc, port)
            print("******restart port-forward success******")
        try:
            # telepresence重启
            telepresence = Telepresence.select()[0]
            telepresence_with_retry(telepresence.k8s_file, restart=True)
            print("******restart telepresence success******")
        except IndexError:
            pass


app = App(__name__)


@app.route('/')
def index():
    try:
        config = Config.select()[0]
        k8s_config_files = [
            i for i in os.listdir(config.k8s_config_path)
            if os.path.isfile(os.path.join(config.k8s_config_path, i))
        ]
    except IndexError:
        config = None
        k8s_config_files = []
    try:
        telepresence = Telepresence.select()[0]
    except IndexError:
        telepresence = None
    try:
        host_config = HostConfig.select()[0]
        hosts = Host.select()
        hosts_dict = {}
        for host in hosts:
            if host.namespace not in hosts_dict:
                hosts_dict[host.namespace] = [host]
            else:
                hosts_dict[host.namespace].append(host)
    except IndexError:
        host_config = None
        hosts_dict = {}
    portforwards =  [p.key.split("###") + [p.subprocess_id]
                     for p in Portforward.select()]
    context = {
        "config": config,
        "k8s_config_files": k8s_config_files,
        "telepresence": telepresence,
        "hosts": {"config": host_config, "hosts_dict": hosts_dict},
        "portforwards": portforwards
    }
    return render_template('index.html', **context)


@app.route('/api', methods=['POST'])
def api():
    operation = request.get_json().get('operation')
    data = request.get_json().get('data')
    try:
        config = Config.select()[0]
    except IndexError:
        config = None
    if operation == 'init':
        if not os.path.isdir(data["k8sConfigPath"]):
            return "无效.kube路径"
        if not os.path.exists(data["kubectlPath"]):
            return "无效kubectl路径"
        if not os.path.exists(data["telepresencePath"]):
            return "无效telepresence路径"
        Config(
            k8s_config_path=data["k8sConfigPath"],
            sudo_password=data["sudoPassword"],
            kubectl_path=data["kubectlPath"],
            telepresence_path=data["telepresencePath"]
        ).save()
    elif operation == 'telepresence':
        telepresence_with_retry(data)
    elif operation == 'telepresenceState':
        return Telepresence.select()[0].state
    elif operation == 'host':
        k8sconfigname = data["k8sConfigName"]
        namespace = data["namespace"]
        k8s_file_path = os.path.join(config.k8s_config_path, k8sconfigname)
        # 获取集群相应命名空间的服务名和集群IP
        host_script_path = os.path.join(base_dir, "script/host.sh")
        kubectl_path = config.kubectl_path
        hosts = os.popen(
            f"sh {host_script_path} {kubectl_path} {k8s_file_path} {namespace}"
        ).read()
        hosts = dict([(i.split("\t")[1], i.split("\t")[0]) for i in hosts.split("\n") if i])
        if hosts:
            try:
                host_config = HostConfig.select()[0]
            except IndexError:
                host_config = HostConfig(k8s_file=k8sconfigname)
                host_config.save()
            if host_config.k8s_file != k8sconfigname:
                host_config.k8s_file = k8sconfigname
                host_config.save()
                Host.delete().execute()
            # 添加host文件的修改权限
            sudo_pwd_cmd = (f"echo {config.sudo_password} | sudo -S"
                            if config.sudo_password else "")
            os.system(f"{sudo_pwd_cmd} chmod o+rw /etc/hosts")
            hosts_file = Hosts(path='/etc/hosts')
            # 先删除同名hosts
            for host_name in hosts:
                hosts_file.remove_all_matching(name=host_name)
            hosts_file.write()
            # 再添加host
            for host_name, ip in hosts.items():
                if ip != "None":
                    new_entry = HostsEntry(
                        entry_type='ipv4', address=ip, names=[host_name])
                    hosts_file.add([new_entry])
                    try:
                        hostobj = Host.get(namespace=namespace, name=host_name)
                        hostobj.ip = ip
                        hostobj.save()
                    except Host.DoesNotExist:
                        Host(namespace=namespace, name=host_name, ip=ip).save()
            hosts_file.write()
    elif operation == 'hostUpdate':
        namespace = data["namespace"]
        host = data["host"]
        ip = data["ip"]
        hostobj = Host.get(namespace=namespace, name=host)
        hostobj.ip = ip
        hostobj.save()
        hosts_file = Hosts(path='/etc/hosts')
        hosts_file.remove_all_matching(name=host)
        new_entry = HostsEntry(
            entry_type='ipv4', address=ip, names=[host])
        hosts_file.add([new_entry])
        hosts_file.write()
    elif operation == 'portforwad':
        k8sconfigname = data["k8sConfigName"]
        namespace = data["namespace"]
        svc = data["svc"]
        port = data["port"]
        config = Config.select()[0]
        # Pod检测
        k8s_file_path = os.path.join(config.k8s_config_path, k8sconfigname)
        kubectl_path = config.kubectl_path
        script_path = os.path.join(base_dir, "script/pod.sh")
        pods = os.popen(
            f"sh {script_path} {kubectl_path} {k8s_file_path} {namespace} {svc} {port}"
        ).read()
        pods = [i.split("\t")[0] for i in pods.split("\n") if i]
        if not pods:
            return "无可用Pods"
        ports = port.split(":")
        if not (len(ports) == 2 and ports[0].isdigit() and int(ports[0]) > 0
                and int(ports[0]) < 65536 and ports[1].isdigit()
                and int(ports[1]) > 0 and int(ports[1]) < 65536):
            return "无效的端口"
        if is_port_in_use(int(ports[0])):
            return "端口已被占用"
        k = f"{k8sconfigname}###{namespace}###{svc}###{port}"
        try:
            Portforward.get(key=k)
            return "PortForward已存在"
        except Portforward.DoesNotExist:
            pass
        Portforward(key=k, subprocess_id="").save()
        portforward_with_retry(k8sconfigname, namespace, svc, port)
        times = 0
        while True:
            portforward = Portforward.get(key=k)
            if portforward.subprocess_id != "" or times > 50:
                break
            times += 1
            time.sleep(0.1)

    elif operation == 'portforwadDelete':
        portforward = Portforward.get(key=data)
        subprocess_id = portforward.subprocess_id
        portforward.delete_instance()
        try:
            os.kill(int(subprocess_id), signal.SIGTERM)
        except Exception:
            pass
    elif operation == 'portforwadReconnect':
        portforward = Portforward.get(key=data)
        subprocess_id = portforward.subprocess_id
        try:
            os.kill(int(subprocess_id), signal.SIGTERM)
        except ProcessLookupError:
            portforward_with_retry(*portforward.key.split("###"))
        times = 0
        while True:
            portforward = Portforward.get(key=data)
            if portforward.subprocess_id != subprocess_id or times > 50:
                break
            times += 1
            time.sleep(0.1)

    return 'ok'


if __name__ == "__main__":
    app.run(debug=True)
