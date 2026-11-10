orchestrate.py is used to perform the various PKI operations between VMs. 
  
  python orchestrate.py check                      check SSH, python3 and sudo on both VMs
  python orchestrate.py deploy -v pq               copy the scripts to both VMs
  python orchestrate.py run -v pq                  deploy + full CA / TLS setup
  python orchestrate.py start-server -v pq         start the TLS test listener (hybrid, pq)
  python orchestrate.py stop-server -v pq

The variant (-v) is classical, hybrid, pq or all (default: all).
