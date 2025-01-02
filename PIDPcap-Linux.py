import subprocess
import re
import signal
import time
import os


def list_processes():
    """List all running processes with their names and PIDs."""
    try:
        ps_output = subprocess.check_output(['ps', '-eo', 'pid,comm'], encoding='utf-8')
    except subprocess.CalledProcessError as e:
        print(f"Error listing processes: {e}")
        return []

    processes = []
    for line in ps_output.splitlines()[1:]:  # Skip header line
        parts = line.split(maxsplit=1)
        if len(parts) == 2:
            pid, name = parts
            processes.append((pid, name))

    return processes


def get_pid_connections(pid):
    """Retrieve IP and port pairs associated with a given PID."""
    try:
        netstat_output = subprocess.check_output(['netstat', '-tunp'], encoding='utf-8')
    except subprocess.CalledProcessError as e:
        print(f"Error running netstat: {e}")
        return []

    connections = set()
    for line in netstat_output.splitlines():
        if re.search(rf'\s{pid}/', line):  # Match lines containing the pid
            parts = line.split()
            local_address, remote_address = parts[3], parts[4]
            local_ip, local_port = local_address.rsplit(':', 1)
            remote_ip, remote_port = remote_address.rsplit(':', 1)
            connections.add((local_ip, local_port, remote_ip, remote_port))

    return connections


def create_tcpdump_filter(connections):
    """Create a tcpdump filter string based on given IP and port pairs."""
    filters = []
    for local_ip, local_port, remote_ip, remote_port in connections:
        filters.append(f"((src host {local_ip} and src port {local_port}) "
                       f"or (dst host {remote_ip} and dst port {remote_port}))")
    return ' or '.join(filters)


def start_tcpdump(filter_expression, pcap_file):
    """Start a tcpdump process with the given filter expression."""
    tcpdump_process = subprocess.Popen(['tcpdump', '-i', 'any', '-w', pcap_file, filter_expression],
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE,
                                       preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_IGN))
    print(f"Capturing traffic with filter: {filter_expression} to file: {pcap_file}")
    return tcpdump_process


def stop_tcpdump(tcpdump_process):
    """Stop the tcpdump process."""
    tcpdump_process.terminate()
    tcpdump_process.wait()
    print("Stopped capture.")


def merge_pcaps(output_file, pcap_files):
    """Merge multiple pcap files into a single file using mergecap."""
    try:
        subprocess.check_output(['mergecap', '-w', output_file] + pcap_files)
        print(f"Merged files into {output_file}")
        for pcap_file in pcap_files:
            os.remove(pcap_file)
    except subprocess.CalledProcessError as e:
        print(f"Error merging pcap files: {e}")


def select_pid():
    """List processes and prompt the user to select a PID."""
    processes = list_processes()
    if not processes:
        print("No processes found.")
        return None

    print("Running processes:")
    for pid, name in processes:
        print(f"{pid}: {name}")

    while True:
        selected_pid = input("Enter the PID of the process you want to monitor: ")
        if any(pid == selected_pid for pid, _ in processes):
            return selected_pid
        else:
            print("Invalid PID. Please try again.")


def main():
    pid = select_pid()
    if not pid:
        return

    previous_connections = set()
    tcpdump_process = None
    pcap_counter = 0
    pcap_files = []

    try:
        while True:
            current_connections = get_pid_connections(pid)
            new_connections = current_connections - previous_connections

            if new_connections:
                previous_connections.update(new_connections)

                if tcpdump_process:
                    stop_tcpdump(tcpdump_process)

                pcap_file = f"output_{pcap_counter}.pcap"
                pcap_counter += 1
                pcap_files.append(pcap_file)

                filter_expression = create_tcpdump_filter(previous_connections)
                tcpdump_process = start_tcpdump(filter_expression, pcap_file)

                merge_pcaps("final_output.pcap", pcap_files)

            time.sleep(5)

    except KeyboardInterrupt:
        print("Interrupted by user.")
    finally:
        if tcpdump_process:
            stop_tcpdump(tcpdump_process)
        merge_pcaps("final_output.pcap", pcap_files)


if __name__ == "__main__":
    main()
