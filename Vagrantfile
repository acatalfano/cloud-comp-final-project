# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/focal64"
  # config.vm.boot_timeout = 600
  config.vm.provider "virtualbox" do |vb|
    vb.gui = true
    vb.memory = "2048"
    vb.customize ["modifyvm", :id, "--graphicscontroller", "vmsvga"]
  end

  PRODUCER_COUNT = 2
  PRODUCER_HOST_BASE = "producer"
  IP_BASE = "192.168.56.1"
  KUBELET_PORT_RANGE_START = 30000
  KUBELET_PORT_RANGE_END = 32767

  # (1..PRODUCER_COUNT).each do |i|
  #   config.vm.define "producer#{i}" do |producer|

  #     # copy public key contents over to each producer's authorized_keys files
  #     # setup proper permissions
  #     public_key = File.read("./producer_key_pair/id_rsa.pub")
  #     $script = <<-SCRIPT
  #       mkdir -p /home/vagrant/.ssh
  #       chmod 700 /home/vagrant/.ssh
  #       echo '#{public_key}' >> /home/vagrant/.ssh/authorized_keys
  #       chmod 600 /home/vagrant/.ssh/authorized_keys
  #       echo 'Host 192.168.*.*' >> /home/vagrant/.ssh/config
  #       echo 'StrictHostKeyChecking no' >> /home/vagrant/.ssh/config
  #       echo 'UserKnownHostsFile /dev/null' >> /home/vagrant/.ssh/config
  #       chmod 600 /home/vagrant/.ssh/config
  #     SCRIPT
  #     producer.vm.provision "shell", inline: $script, privileged: false

  #     # configure network for each producer
  #     hostname = "#{PRODUCER_HOST_BASE}#{i}"
  #     producer.vm.hostname = hostname
  #     producer.vm.network "private_network", ip: "#{IP_BASE}#{i}"
  #     producer.vm.network "forwarded_port", guest: 22, host: 2210 + i, id: "ssh"
  #     producer.vm.network "forwarded_port", guest: 8080, host: 30000 + i, id: "http alternative"
  #     # producer.vm.network "forwarded_port", guest: 80, host: 30100 + i, id: "http"
  #     # producer.vm.network "forwarded_port", guest: 443, host: 30200 + i, id: "https"

  #     # producer.vm.network "forwarded_port", guest: 8285, host: 30000 + i, id: "flannel 1", protocol: "udp"
  #     # producer.vm.network "forwarded_port", guest: 8472, host: 30100 + i, id: "flannel 2", protocol: "udp"

  #     producer.vm.network "forwarded_port", guest: 6443, host: 30300 + i, id: "k8s control"
  #     producer.vm.network "forwarded_port", guest: 2379, host: 30400 + i, id: "etcd server client api 1"
  #     producer.vm.network "forwarded_port", guest: 2380, host: 30500 + i, id: "etcd server client api 1"
  #     producer.vm.network "forwarded_port", guest: 10259, host: 30600 + i, id: "kube-scheudler"
  #     producer.vm.network "forwarded_port", guest: 10257, host: 30700 + i, id: "kube-controller-manager"
  #     producer.vm.network "forwarded_port", guest: 10250, host: 30900 + i, id: "kubelet api 1"
  #     # producer.vm.network "forwarded_port", guest: 10251, host: 31000 + i, id: "kubelet api 2"
  #     # producer.vm.network "forwarded_port", guest: 10252, host: 31100 + i, id: "kubelet api 3"

  #     # configure nodePort services ports
  #     # (KUBELET_PORT_RANGE_END - KUBELET_PORT_RANGE_START + 1).times do |j|
  #     #   producer.vm.network "forwarded_port",
  #     #     guest: KUBELET_PORT_RANGE_START + j,
  #     #     host: 31100 + (i * 100) + j,
  #     #     id: "#{PRODUCER_HOST_BASE}#{i} nodePort #{j}"
  #     # end

  #     producer.vm.provider "virtualbox" do |vb|
  #       vb.customize ["modifyvm", :id, "--name", hostname]
  #     end
  #   end
  # end

  config.vm.define "provisioner" do |provisioner|
    provisioner.vm.hostname = "provisioner"
    # provisioner.vm.provision "file", source: "./producer_key_pair/id_rsa", destination: "/home/vagrant/.ssh/producer_id_rsa"
    # provisioner.vm.provision "shell", inline: "chmod 600 /home/vagrant/.ssh/producer_id_rsa", privileged: false

    provisioner.vm.provider :virtualbox do |vb|
      vb.customize ["modifyvm", :id, "--name", "provisioner"]
    end

    # configure hosts file so provisioner's DNS knows about the producers
    # $script = <<-SCRIPT
    #   for i in {1..#{PRODUCER_COUNT}}
    #   do
    #     echo "#{IP_BASE}$i #{PRODUCER_HOST_BASE}$i"
    #   done |
    #   sudo tee -a /etc/hosts > /dev/null
    # SCRIPT
    # provisioner.vm.provision "shell", inline: $script, privileged: false
    provisioner.vm.provision "shell", path: "./bootstrap.sh"
    provisioner.vm.provision "file", source: "./rsa_private.pem", destination: "/home/vagrant/.ssh/id_rsa"

    # copy AWS credentials
    provisioner.vm.provision "file", source: ".aws", destination: "/home/vagrant/.aws"

    # let's also copy our ansible.cfg, MyInventory and cloud.yaml file
    provisioner.vm.provision "file", source: "./ansible.cfg", destination: "/home/vagrant/.ansible.cfg"
    provisioner.vm.provision "file", source: "./Inventory", destination: "/home/vagrant/Inventory"

    # Ansible provisioner
    provisioner.vm.provision "ansible_local" do |ansible|
      # TODO: drop this line later vvvv
      # ansible.playbook = "./playbook_test.yml"
      ansible.playbook = "./playbook_master.yml"
      # ansible.playbook = "./playbook_master_cleanup.yml"
      ansible.install_mode = :pip
      ansible.pip_install_cmd = "sudo apt-get install -y python3-distutils python3-pip" #curl https://bootstrap.pypa.io/get-pip.py | sudo python3"
      ansible.verbose = true
      ansible.install = true  # installs ansible (and hence python) on VM
      ansible.limit = "all"
      ansible.inventory_path = "/home/vagrant/Inventory"  # inventory file
    end
  end
end
