"""
Prometheus collecters for Proxmox VE cluster.
"""
# pylint: disable=too-few-public-methods

import itertools
from proxmoxer import ProxmoxAPI

from prometheus_client import CollectorRegistry, generate_latest
from prometheus_client.core import GaugeMetricFamily
import sensors
import subprocess
import re
import stat
import os

class StatusCollector(object):
    """
    Collects Proxmox VE Node/VM/CT-Status

    # HELP pve_up Node/VM/CT-Status is online/running
    # TYPE pve_up gauge
    pve_up{id="node/proxmox-host"} 1.0
    pve_up{id="cluster/pvec"} 1.0
    pve_up{id="lxc/101"} 1.0
    pve_up{id="qemu/102"} 1.0
    """

    def __init__(self, pve):
        self._pve = pve

    def collect(self): # pylint: disable=missing-docstring
        status_metrics = GaugeMetricFamily(
            'pve_up',
            'Node/VM/CT-Status is online/running',
            labels=['id'])

        for entry in self._pve.cluster.status.get():
            if entry['type'] == 'node':
                label_values = [entry['id']]
                status_metrics.add_metric(label_values, entry['online'])
            elif entry['type'] == 'cluster':
                label_values = ['cluster/{:s}'.format(entry['name'])]
                status_metrics.add_metric(label_values, entry['quorate'])
            else:
                raise ValueError('Got unexpected status entry type {:s}'.format(entry['type']))

        for resource in self._pve.cluster.resources.get(type='vm'):
            label_values = [resource['id']]
            status_metrics.add_metric(label_values, resource['status'] == 'running')

        yield status_metrics

class VersionCollector(object):
    """
    Collects Proxmox VE build information. E.g.:

    # HELP pve_version_info Proxmox VE version info
    # TYPE pve_version_info gauge
    pve_version_info{release="15",repoid="7599e35a",version="4.4"} 1.0
    """

    LABEL_WHITELIST = ['release', 'repoid', 'version']

    def __init__(self, pve):
        self._pve = pve

    def collect(self): # pylint: disable=missing-docstring
        version_items = self._pve.version.get().items()
        version = {key: value for key, value in version_items if key in self.LABEL_WHITELIST}

        labels, label_values = zip(*version.items())
        metric = GaugeMetricFamily(
            'pve_version_info',
            'Proxmox VE version info',
            labels=labels
        )
        metric.add_metric(label_values, 1)

        yield metric

class ClusterNodeCollector(object):
    """
    Collects Proxmox VE cluster node information. E.g.:

    # HELP pve_node_info Node info
    # TYPE pve_node_info gauge
    pve_node_info{id="node/proxmox-host", ip="10.20.30.40", level="c",
        local="1", name="proxmox-host", nodeid="0"} 1.0
    """

    def __init__(self, pve):
        self._pve = pve

    def collect(self): # pylint: disable=missing-docstring
        nodes = [entry for entry in self._pve.cluster.status.get() if entry['type'] == 'node']

        if nodes:
            # Remove superflous keys.
            for node in nodes:
                del node['type']
                del node['online']

            # Yield remaining data.
            labels = nodes[0].keys()
            info_metrics = GaugeMetricFamily(
                'pve_node_info',
                'Node info',
                labels=labels)

            for node in nodes:
                label_values = [str(node[key]) for key in labels]
                info_metrics.add_metric(label_values, 1)

            yield info_metrics

class ClusterInfoCollector(object):
    """
    Collects Proxmox VE cluster information. E.g.:

    # HELP pve_cluster_info Cluster info
    # TYPE pve_cluster_info gauge
    pve_cluster_info{id="cluster/pvec",nodes="2",quorate="1",version="2"} 1.0
    """

    def __init__(self, pve):
        self._pve = pve

    def collect(self): # pylint: disable=missing-docstring
        clusters = [entry for entry in self._pve.cluster.status.get() if entry['type'] == 'cluster']

        if clusters:
            # Remove superflous keys.
            for cluster in clusters:
                del cluster['type']

            # Add cluster-prefix to id.
            for cluster in clusters:
                cluster['id'] = 'cluster/{:s}'.format(cluster['name'])
                del cluster['name']

            # Yield remaining data.
            labels = clusters[0].keys()
            info_metrics = GaugeMetricFamily(
                'pve_cluster_info',
                'Cluster info',
                labels=labels)

            for cluster in clusters:
                label_values = [str(cluster[key]) for key in labels]
                info_metrics.add_metric(label_values, 1)

            yield info_metrics

class ClusterResourcesCollector(object):
    """
    Collects Proxmox VE cluster resources information, i.e. memory, storage, cpu
    usage for cluster nodes and guests.
    """

    def __init__(self, pve):
        self._pve = pve

    def collect(self): # pylint: disable=missing-docstring
        metrics = {
            'maxdisk': GaugeMetricFamily(
                'pve_disk_size_bytes',
                'Size of storage device',
                labels=['id']),
            'disk': GaugeMetricFamily(
                'pve_disk_usage_bytes',
                'Disk usage in bytes',
                labels=['id']),
            'maxmem': GaugeMetricFamily(
                'pve_memory_size_bytes',
                'Size of memory',
                labels=['id']),
            'mem': GaugeMetricFamily(
                'pve_memory_usage_bytes',
                'Memory usage in bytes',
                labels=['id']),
            'netout': GaugeMetricFamily(
                'pve_network_transmit_bytes',
                'Number of bytes transmitted over the network',
                labels=['id']),
            'netin': GaugeMetricFamily(
                'pve_network_receive_bytes',
                'Number of bytes received over the network',
                labels=['id']),
            'diskwrite': GaugeMetricFamily(
                'pve_disk_write_bytes',
                'Number of bytes written to storage',
                labels=['id']),
            'diskread': GaugeMetricFamily(
                'pve_disk_read_bytes',
                'Number of bytes read from storage',
                labels=['id']),
            'cpu': GaugeMetricFamily(
                'pve_cpu_usage_ratio',
                'CPU usage (value between 0.0 and pve_cpu_usage_limit)',
                labels=['id']),
            'maxcpu': GaugeMetricFamily(
                'pve_cpu_usage_limit',
                'Maximum allowed CPU usage',
                labels=['id']),
            'uptime': GaugeMetricFamily(
                'pve_uptime_seconds',
                'Number of seconds since the last boot',
                labels=['id']),
        }

        info_metrics = {
            'guest': GaugeMetricFamily(
                'pve_guest_info',
                'VM/CT info',
                labels=['id', 'node', 'name', 'type']),
            'storage': GaugeMetricFamily(
                'pve_storage_info',
                'Storage info',
                labels=['id', 'node', 'storage']),
        }

        info_lookup = {
            'lxc': {
                'labels': ['id', 'node', 'name', 'type'],
                'gauge': info_metrics['guest'],
            },
            'qemu': {
                'labels': ['id', 'node', 'name', 'type'],
                'gauge': info_metrics['guest'],
            },
            'storage': {
                'labels': ['id', 'node', 'storage'],
                'gauge': info_metrics['storage'],
            },
        }

        for resource in self._pve.cluster.resources.get():
            restype = resource['type']

            if restype in info_lookup:
                label_values = [resource.get(key, '') for key in info_lookup[restype]['labels']]
                info_lookup[restype]['gauge'].add_metric(label_values, 1)

            label_values = [resource['id']]
            for key, metric_value in resource.items():
                if key in metrics:
                    metrics[key].add_metric(label_values, metric_value)

        return itertools.chain(metrics.values(), info_metrics.values())

class LMSensorsCollector:
    """
    Collects Proxmox VE host sensors information. E.g.:

    # HELP pve_version_info Proxmox VE version info
    # TYPE pve_version_info gauge
    pve_version_info{release="15",repoid="7599e35a",version="4.4"} 1.0
    """

    def collect(self): # pylint: disable=missing-docstring
        status_metrics = GaugeMetricFamily(
            'pve_host_sensors',
            'Sensors in each chip',
            labels=['chip','chip_type','sensor'])

        sensors.init()
        try:
            for chip in sensors.iter_detected_chips():
                for feature in chip:
                    status_metrics.add_metric([str(chip), chip.adapter_name, feature.label], feature.get_value())
        except:
            print("Error while reading chip information")
        finally:
            sensors.cleanup()

        yield status_metrics

class CPUFreqCollector:
    def collect(self):
        status_metrics = GaugeMetricFamily(
            'pve_host_cpufreq',
            'CPU freq info',
            labels=['max_freq', 'min_freq'])

        out = subprocess.Popen(['lscpu'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, _ = out.communicate()
        for l in stdout.split(b"\n"):
            if l.startswith(b"CPU MHz"):
                cur_freq = float(l.split(b":")[1].lstrip())
            elif l.startswith(b"CPU max MHz"):
                max_freq = l.split(b":")[1].lstrip().decode("utf-8")
            elif l.startswith(b"CPU min MHz"):
                min_freq = l.split(b":")[1].lstrip().decode("utf-8")
        status_metrics.add_metric([max_freq, min_freq], cur_freq)

        yield status_metrics

class HDDTempCollector:
    def collect(self):
        status_metrics = GaugeMetricFamily(
            'pve_host_hdd_temp',
            'Host HDD temp information',
            labels=['device', 'mode'])

        def __disk_exists(path):
            try:
                return stat.S_ISBLK(os.stat(path).st_mode)
            except:
                return False

        availed_disk = []
        for al in ('a','b','c','d','e'):
            p = "/dev/sd{}".format(al)
            if __disk_exists(p):
                availed_disk.append(p)

        cmd_params = ['hddtemp']
        cmd_params.extend(availed_disk)
        out = subprocess.Popen(cmd_params, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, _ = out.communicate()
        for l in stdout.split(b"\n"):
            if len(l) > 0:
                p = l.split(b":")
                status_metrics.add_metric(
                    [p[0].strip().decode("utf-8"), p[1].strip().decode("utf-8")],
                    float(re.search(b'\d+', p[2].strip()).group())
                )

        yield status_metrics

def collect_pve(config, host):
    """Scrape a host and return prometheus text format for it"""

    pve = ProxmoxAPI(host, **config)

    registry = CollectorRegistry()
    registry.register(StatusCollector(pve))
    registry.register(ClusterResourcesCollector(pve))
    registry.register(ClusterNodeCollector(pve))
    registry.register(ClusterInfoCollector(pve))
    registry.register(VersionCollector(pve))
    registry.register(LMSensorsCollector())
    registry.register(CPUFreqCollector())
    registry.register(HDDTempCollector())
    return generate_latest(registry)
