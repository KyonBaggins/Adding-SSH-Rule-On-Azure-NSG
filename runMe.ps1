# 从控制台请求订阅名输入
$subsName = Read-Host 'Input the name of the subscription'

# 切换订阅
Select-AzSubscription -SubscriptionName $subsName
# 获取当前订阅下所有网络安全组
$nsgList = Get-AzNetworkSecurityGroup

foreach ($nsg in $nsgList) {
    # 初始化网络接口动态数组
    $nicList = New-Object System.Collections.ArrayList

    # 网络安全组关联到网络接口，遍历并添加到动态数组
    if ($nsg.NetworkInterfaces.Length -gt 0) {
        foreach ($nicSingle in $nsg.NetworkInterfaces) {
            [void]$nicList.Add($nicSingle.Id);
        }
    }
    # 网络安全组关联到子网，遍历子网，添加关联到子网的网络接口并添加到动态数组
    if ($nsg.Subnets.Length -gt 0) {
        foreach ($subnet in $nsg.Subnets) {
            $allNic = Get-AzNetworkInterface
            # 遍历网络接口，将关联到当前子网的网络接口添加到动态数组
            foreach ($nicInSubnet in $allNic) {
                if ($nicInSubnet.IpConfigurations.Subnet.Id = $subnet.Id) {
                    [void]$nicList.Add($nicInSubnet.Id);
                }
            }
        }
    }
        
    # 判断当前网络安全组影响的网络接口是否关联到Linux虚拟机，如是则添加指定入站规则
    foreach ($nicId in $nicList) {
        $thisNic = Get-AzNetworkInterface -ResourceId $nicId
        if ($Null -ne $thisNic.VirtualMachine.Id) {
            # 当前网络接口关联到虚拟机，获取虚拟机
            $thisVM = Get-AzVM -Name $thisNic.VirtualMachine.Id.Split('/')[8] -ResourceGroupName $thisNic.VirtualMachine.Id.Split('/')[4]
            if ($thisVM.StorageProfile.OsDisk.OsType -eq 'Linux') {
                # 当前网络接口关联的虚拟机为Linux虚拟机，在当前网络安全组添加对应入站访问规则，跳出循环
                Write-Host "Found Linux VM $($thisVM.Name), adding security rule for NSG $($nsg.Name)." -ForegroundColor Yellow

                $rulePrior = 100
                while ($rulePrior -le 4096) {
                    $rst = $nsg | Add-AzNetworkSecurityRuleConfig -Name 'AllowAnsibleInbound' -Description 'Allow Ansible inbound to port 22' -Access Allow -Protocol * -Direction Inbound -Priority $rulePrior -SourceAddressPrefix "139.217.223.134" -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 22 -ErrorAction SilentlyContinue
                    $rst = $nsg | Set-AzNetworkSecurityGroup -ErrorAction SilentlyContinue
                    
                    if ($Null -ne $rst) {
                        # 判断添加的安全规则是否与已有规则优先级冲突，不冲突则跳出循环
                        break
                    }
                    
                    # 添加的安全规则与已有规则优先级发生冲突，删除当前的冲突规则配置
                    $nsg = Remove-AzNetworkSecurityRuleConfig -Name 'AllowFNAnsibleInbound' -NetworkSecurityGroup $nsg
                    $rulePrior ++
                }
                break
            }
        }
        Write-Host "Found no Linux VM, skip NIC $($thisNic.Name) in NSG $($nsg.Name)." -ForegroundColor Yellow
    }
}
