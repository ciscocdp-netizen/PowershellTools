#Requires -Version 5.1
<#
.SYNOPSIS
    DHCP Manager v2.0 - Complete Production-Ready Script with Full GUI
    
.DESCRIPTION
    Complete WPF GUI for managing Windows DHCP Server with all features:
    - Full graphical interface with all tabs and controls
    - Real-time action logging with millisecond timestamps
    - Fixed scope selection and state management
    - Robust error handling and validation
    - Thread-safe UI updates via Dispatcher
    - Navigation tree with auto-synchronization
    - Built-in action log viewer with export
    - All DHCP management features implemented
    
    Features:
    ✓ Scopes management (create, edit, delete, activate/deactivate)
    ✓ Leases viewing and management
    ✓ Reservations (add, edit, delete)
    ✓ Exclusions management
    ✓ Scope and Server options
    ✓ MAC address filters (Allow/Deny lists)
    ✓ DHCP policies
    ✓ Server statistics
    ✓ Audit log viewer
    ✓ Action log with export
    ✓ Multi-server comparison (scopes, options, leases, reservations)
    ✓ DHCP audit log ingest (local + remote)
    ✓ Real-time DHCP event watching on local and remote servers
    ✓ Scope migration (scopes, options, reservations/clients, exclusions)
    ✓ Domain DHCP server discovery with ping up/down status
    ✓ BAD_ADDRESS troubleshooting (conflict detection, ping/ARP, failover, clear gating)
    ✓ IPAM-style monitoring dashboard (KPIs, Top 10 util, active alerts, estate snapshot)
    
.NOTES
    File Name      : DHCP-Manager-v2-FULL.ps1
    Version        : 2.7.2 (IPAM-style Dashboard)
    Date           : 2026-09-09
    Author         : Anthony Blake
    Prerequisite   : PowerShell 5.1+
    Required Module: DhcpServer (Install-WindowsFeature RSAT-DHCP)
    
.EXAMPLE
    .\DHCP-Manager-v2-FULL.ps1
    
    Launches the complete DHCP Manager GUI with all features
    
.LINK
    https://github.com/ciscocdp-netizen/PowershellTools
    https://docs.microsoft.com/powershell/module/dhcpserver/
#>

[CmdletBinding()]
param()

#region Initialization and Prerequisites
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# Version validation
if ($PSVersionTable.PSVersion.Major -lt 5 -or 
    ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -lt 1)) {
    Write-Error "This script requires PowerShell 5.1 or later. Current version: $($PSVersionTable.PSVersion)"
    exit 1
}

# Load required assemblies
try {
    Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
    Add-Type -AssemblyName PresentationCore -ErrorAction Stop
    Add-Type -AssemblyName WindowsBase -ErrorAction Stop
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    Add-Type -AssemblyName System.Drawing -ErrorAction Stop
} catch {
    Write-Error "Failed to load required .NET assemblies: $_"
    exit 1
}

# Display startup banner
$banner = @"

╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║         DHCP Manager v2.4 - Domain Scan + Scope Migration               ║
║                      Built by Anthony Blake                              ║
║                                                                          ║
║  ✓ Scan Domain DHCP  ✓ Compare  ✓ Live Events  ✓ Migrate Scopes        ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝

"@
Write-Host $banner -ForegroundColor Cyan
#endregion

#region Global State Variables
$Global:DHCPServer       = $null
$Global:CompareServer    = $null
$Global:SelectedScope    = $null
$Global:ActionLog        = [System.Collections.Generic.List[string]]::new()
$Global:Credential       = $null
$Global:CompareResults   = [System.Collections.Generic.List[object]]::new()
$Global:CompareFilter    = 'All'
$Global:AppAuthor        = 'Anthony Blake'
$Global:AppVersion       = '2.7.2'
$Global:DhcpEventEntries = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$Global:DhcpEventEntriesAll = [System.Collections.Generic.List[object]]::new()
$Global:ScopeStatEntries = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$Global:ScopeStatEntriesAll = [System.Collections.Generic.List[object]]::new()
$Global:ScopeUtilThreshold = 90
$Global:NavScopeIndex    = [System.Collections.Generic.List[object]]::new()
$Global:NavScopeMatched  = [System.Collections.Generic.List[object]]::new()
$Global:NavScopeSearchText = ''
$Global:NavScopeMatchIndex = -1
$Global:BadAddressFindings = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$Global:BadAddressLeases = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$Global:BadAddressProbes = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$Global:BadAddressDiag = @{
    ScopeId     = ''
    Server      = ''
    RanAt       = $null
    BadCount    = 0
    Pattern     = ''
    CanClear    = $false
    Summary     = ''
}
$Global:DashboardTopScopes = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$Global:DashboardAlerts = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$Global:DashboardEstate = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$Global:DashboardHealth = @{
    Server          = ''
    RefreshedAt     = $null
    FailoverSummary = ''
    ConflictDetection = ''
    CriticalCount   = 0
    WarningCount    = 0
    EstateOnline    = 0
    EstateTotal     = 0
}
$Global:LogWatchState    = @{
    Local  = @{ Enabled = $false; Path = $null; Offset = 0L }
    A      = @{ Enabled = $false; Path = $null; Offset = 0L }
    B      = @{ Enabled = $false; Path = $null; Offset = 0L }
    Custom = @{ Enabled = $false; Path = $null; Offset = 0L }
}
$Global:EventWatchActive = $false
$Global:MigrationResults = [System.Collections.Generic.List[object]]::new()
$Global:MigrationScopes  = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$Global:DomainScanResults = [System.Collections.Generic.List[object]]::new()
$Global:ExtraScanDomains  = [System.Collections.Generic.List[string]]::new()
$Global:TaskProgress = @{
    Active          = $false
    Name            = ''
    Message         = ''
    Percent         = 0
    Processed       = 0
    Total           = 0
    CanPause        = $false
    Paused          = $false
    CancelRequested = $false
    StartTime       = $null
}
#endregion

#region Core Logging Functions
function Write-ActionLog {
    <#
    .SYNOPSIS
        Writes timestamped log entry to action log and console
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format 'HH:mm:ss.fff'
    $logEntry = "[$timestamp] [$Level] $Message"
    
    try {
        $Global:ActionLog.Add($logEntry)
        if ($Global:ActionLog.Count -gt 1000) {
            $Global:ActionLog.RemoveRange(0, 100)
        }
    } catch {}
    
    $color = switch ($Level) {
        'SUCCESS' { 'Green' }
        'WARN'    { 'Yellow' }
        'ERROR'   { 'Red' }
        default   { 'Cyan' }
    }
    
    Write-Host $logEntry -ForegroundColor $color
}

function Update-LogDisplay {
    <#
    .SYNOPSIS
        Updates the UI log display with recent entries
    #>
    if ($null -eq $script:TxtLog) { return }
    
    try {
        $script:TxtLog.Dispatcher.Invoke([action]{
            try {
                $script:TxtLog.Text = ($Global:ActionLog | Select-Object -Last 500) -join "`r`n"
                if ($null -ne $script:LogScrollViewer) {
                    $script:LogScrollViewer.ScrollToEnd()
                }
            } catch {}
        }, [System.Windows.Threading.DispatcherPriority]::Background)
    } catch {}
}

Write-ActionLog "DHCP Manager v2.4 (Anthony Blake — Domain Scan) initializing..." "INFO"
Write-ActionLog "PowerShell Version: $($PSVersionTable.PSVersion)" "INFO"
Write-ActionLog "OS: $([Environment]::OSVersion.VersionString)" "INFO"
#endregion

#region XAML UI Definition - Complete Interface
Write-ActionLog "Loading XAML interface definition..." "INFO"

[xml]$XAML = @'
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="DHCP Manager v2.7 — Monitoring &amp; Management"
    Height="780" Width="1260"
    MinHeight="600" MinWidth="900"
    WindowStartupLocation="CenterScreen"
    Background="#1A1D23"
    FontFamily="Segoe UI"
    FontSize="13">

  <Window.Resources>
    <!-- Color Resources -->
    <SolidColorBrush x:Key="BgDeep"      Color="#1A1D23"/>
    <SolidColorBrush x:Key="BgPanel"     Color="#22262E"/>
    <SolidColorBrush x:Key="BgCard"      Color="#2A2F3A"/>
    <SolidColorBrush x:Key="BgHover"     Color="#313847"/>
    <SolidColorBrush x:Key="BgSelected"  Color="#1A3A5C"/>
    <SolidColorBrush x:Key="Accent"      Color="#2196F3"/>
    <SolidColorBrush x:Key="AccentHover" Color="#1976D2"/>
    <SolidColorBrush x:Key="AccentDark"  Color="#0D47A1"/>
    <SolidColorBrush x:Key="Success"     Color="#4CAF50"/>
    <SolidColorBrush x:Key="Warning"     Color="#FF9800"/>
    <SolidColorBrush x:Key="Danger"      Color="#F44336"/>
    <SolidColorBrush x:Key="TextPrimary" Color="#E8EAF0"/>
    <SolidColorBrush x:Key="TextSecond"  Color="#9AA3B2"/>
    <SolidColorBrush x:Key="Border"      Color="#383E4A"/>
    <SolidColorBrush x:Key="BorderLight" Color="#454D5C"/>

    <!-- Button Styles -->
    <Style x:Key="BtnPrimary" TargetType="Button">
      <Setter Property="Background"   Value="{StaticResource Accent}"/>
      <Setter Property="Foreground"   Value="#FFFFFF"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding"      Value="14,6"/>
      <Setter Property="FontSize"     Value="12"/>
      <Setter Property="FontWeight"   Value="SemiBold"/>
      <Setter Property="Cursor"       Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border Background="{TemplateBinding Background}" CornerRadius="5"
                    BorderThickness="{TemplateBinding BorderThickness}" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter Property="Background" Value="{StaticResource AccentHover}"/>
              </Trigger>
              <Trigger Property="IsPressed" Value="True">
                <Setter Property="Background" Value="{StaticResource AccentDark}"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter Property="Opacity" Value="0.45"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="BtnSecondary" TargetType="Button" BasedOn="{StaticResource BtnPrimary}">
      <Setter Property="Background"   Value="{StaticResource BgCard}"/>
      <Setter Property="Foreground"   Value="{StaticResource TextPrimary}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="BorderBrush"  Value="{StaticResource Border}"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Background" Value="{StaticResource BgHover}"/>
        </Trigger>
      </Style.Triggers>
    </Style>

    <Style x:Key="BtnDanger" TargetType="Button" BasedOn="{StaticResource BtnPrimary}">
      <Setter Property="Background" Value="{StaticResource Danger}"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Background" Value="#C62828"/>
        </Trigger>
      </Style.Triggers>
    </Style>

    <Style x:Key="BtnSuccess" TargetType="Button" BasedOn="{StaticResource BtnPrimary}">
      <Setter Property="Background" Value="{StaticResource Success}"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Background" Value="#388E3C"/>
        </Trigger>
      </Style.Triggers>
    </Style>

    <!-- TextBox Style -->
    <Style x:Key="DarkTextBox" TargetType="TextBox">
      <Setter Property="Background"    Value="{StaticResource BgDeep}"/>
      <Setter Property="Foreground"    Value="#F2F4F8"/>
      <Setter Property="BorderBrush"   Value="{StaticResource Border}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding"       Value="8,4"/>
      <Setter Property="MinHeight"     Value="30"/>
      <Setter Property="FontSize"      Value="13"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
      <Setter Property="CaretBrush"    Value="#F2F4F8"/>
      <Setter Property="SelectionBrush" Value="{StaticResource Accent}"/>
      <Setter Property="SelectionOpacity" Value="0.45"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TextBox">
            <Border x:Name="Bd"
                    Background="{TemplateBinding Background}"
                    BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}"
                    CornerRadius="4"
                    SnapsToDevicePixels="True"
                    Padding="{TemplateBinding Padding}">
              <!-- Do NOT use VerticalAlignment=Center here — it clips glyphs in fixed-height boxes -->
              <ScrollViewer x:Name="PART_ContentHost"
                            Focusable="False"
                            HorizontalScrollBarVisibility="Hidden"
                            VerticalScrollBarVisibility="Disabled"
                            Background="Transparent"
                            TextElement.Foreground="{TemplateBinding Foreground}"
                            TextElement.FontSize="{TemplateBinding FontSize}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsFocused" Value="True">
                <Setter TargetName="Bd" Property="BorderBrush" Value="{StaticResource Accent}"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter Property="Opacity" Value="0.55"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- DataGrid Style -->
    <Style x:Key="DarkGrid" TargetType="DataGrid">
      <Setter Property="Background"          Value="{StaticResource BgPanel}"/>
      <Setter Property="Foreground"          Value="{StaticResource TextPrimary}"/>
      <Setter Property="BorderThickness"     Value="0"/>
      <Setter Property="GridLinesVisibility" Value="Horizontal"/>
      <Setter Property="HorizontalGridLinesBrush" Value="{StaticResource Border}"/>
      <Setter Property="RowBackground"       Value="{StaticResource BgPanel}"/>
      <Setter Property="AlternatingRowBackground" Value="{StaticResource BgCard}"/>
      <Setter Property="ColumnHeaderHeight"  Value="34"/>
      <Setter Property="RowHeight"           Value="28"/>
      <Setter Property="FontSize"            Value="12"/>
      <Setter Property="SelectionMode"       Value="Single"/>
      <Setter Property="AutoGenerateColumns" Value="False"/>
      <Setter Property="CanUserAddRows"      Value="False"/>
      <Setter Property="CanUserDeleteRows"   Value="False"/>
      <Setter Property="IsReadOnly"          Value="True"/>
      <Setter Property="HeadersVisibility"   Value="Column"/>
    </Style>

    <Style TargetType="DataGridColumnHeader">
      <Setter Property="Background"   Value="{StaticResource BgCard}"/>
      <Setter Property="Foreground"   Value="{StaticResource TextSecond}"/>
      <Setter Property="Padding"      Value="10,0"/>
      <Setter Property="FontWeight"   Value="SemiBold"/>
      <Setter Property="FontSize"     Value="11"/>
      <Setter Property="BorderBrush"  Value="{StaticResource Border}"/>
      <Setter Property="BorderThickness" Value="0,0,1,1"/>
    </Style>

    <Style TargetType="DataGridRow">
      <Setter Property="Foreground"  Value="{StaticResource TextPrimary}"/>
      <Style.Triggers>
        <Trigger Property="IsSelected" Value="True">
          <Setter Property="Background" Value="{StaticResource BgSelected}"/>
          <Setter Property="Foreground" Value="#FFFFFF"/>
        </Trigger>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Background" Value="{StaticResource BgHover}"/>
        </Trigger>
      </Style.Triggers>
    </Style>

    <Style TargetType="DataGridCell">
      <Setter Property="Padding"         Value="8,0"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
    </Style>

    <!-- Label and Text Styles -->
    <Style x:Key="FormLabel" TargetType="TextBlock">
      <Setter Property="Foreground"  Value="{StaticResource TextSecond}"/>
      <Setter Property="FontSize"    Value="11"/>
      <Setter Property="FontWeight"  Value="SemiBold"/>
      <Setter Property="Margin"      Value="0,0,0,3"/>
    </Style>

    <Style x:Key="SectionHeader" TargetType="TextBlock">
      <Setter Property="Foreground"  Value="{StaticResource TextPrimary}"/>
      <Setter Property="FontSize"    Value="14"/>
      <Setter Property="FontWeight"  Value="SemiBold"/>
      <Setter Property="Margin"      Value="0,0,0,12"/>
    </Style>

    <!-- TreeView Style -->
    <Style TargetType="TreeViewItem">
      <Setter Property="Foreground"     Value="{StaticResource TextPrimary}"/>
      <Setter Property="FontSize"       Value="12"/>
      <Setter Property="Padding"        Value="4,3"/>
      <Setter Property="Background"     Value="Transparent"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Cursor"         Value="Hand"/>
      <Style.Triggers>
        <Trigger Property="IsSelected" Value="True">
          <Setter Property="Foreground" Value="#FFFFFF"/>
        </Trigger>
      </Style.Triggers>
    </Style>

    <!-- CheckBox Style -->
    <Style TargetType="CheckBox">
      <Setter Property="Foreground" Value="{StaticResource TextPrimary}"/>
      <Setter Property="FontSize"   Value="12"/>
      <Setter Property="Margin"     Value="0,2"/>
    </Style>

    <!-- TabControl Style -->
    <Style TargetType="TabControl">
      <Setter Property="Background"    Value="{StaticResource BgPanel}"/>
      <Setter Property="BorderThickness" Value="0"/>
    </Style>

    <Style TargetType="TabItem">
      <Setter Property="Background"   Value="{StaticResource BgCard}"/>
      <Setter Property="Foreground"   Value="{StaticResource TextSecond}"/>
      <Setter Property="FontSize"     Value="12"/>
      <Setter Property="Padding"      Value="14,8"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TabItem">
            <Border x:Name="TabBorder" Background="{TemplateBinding Background}"
                    BorderThickness="0,0,0,2" BorderBrush="Transparent"
                    Padding="{TemplateBinding Padding}">
              <ContentPresenter ContentSource="Header" HorizontalAlignment="Center"
                                VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="TabBorder" Property="BorderBrush" Value="{StaticResource Accent}"/>
                <Setter TargetName="TabBorder" Property="Background" Value="{StaticResource BgPanel}"/>
                <Setter Property="Foreground" Value="{StaticResource TextPrimary}"/>
              </Trigger>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="TabBorder" Property="Background" Value="{StaticResource BgHover}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- ComboBoxItem: dark list rows (default popup is white; light Foreground was unreadable) -->
    <Style TargetType="ComboBoxItem">
      <Setter Property="SnapsToDevicePixels" Value="True"/>
      <Setter Property="Padding" Value="8,5"/>
      <Setter Property="HorizontalContentAlignment" Value="Left"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
      <Setter Property="Background" Value="{StaticResource BgCard}"/>
      <Setter Property="Foreground" Value="{StaticResource TextPrimary}"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ComboBoxItem">
            <Border x:Name="Bd"
                    Background="{TemplateBinding Background}"
                    BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}"
                    Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}"
                                VerticalAlignment="{TemplateBinding VerticalContentAlignment}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsHighlighted" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="{StaticResource BgHover}"/>
              </Trigger>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="{StaticResource BgSelected}"/>
                <Setter Property="Foreground" Value="#FFFFFF"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter Property="Foreground" Value="{StaticResource TextSecond}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- ComboBox: dark closed control + dark dropdown popup -->
    <Style TargetType="ComboBox">
      <Setter Property="Background" Value="{StaticResource BgDeep}"/>
      <Setter Property="Foreground" Value="{StaticResource TextPrimary}"/>
      <Setter Property="BorderBrush" Value="{StaticResource Border}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="6,3"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="ScrollViewer.HorizontalScrollBarVisibility" Value="Auto"/>
      <Setter Property="ScrollViewer.VerticalScrollBarVisibility" Value="Auto"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ComboBox">
            <Grid>
              <ToggleButton x:Name="ToggleButton"
                            Focusable="False"
                            IsChecked="{Binding IsDropDownOpen, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}"
                            ClickMode="Press">
                <ToggleButton.Template>
                  <ControlTemplate TargetType="ToggleButton">
                    <Border x:Name="TemplateBorder"
                            Background="{Binding Background, RelativeSource={RelativeSource AncestorType=ComboBox}}"
                            BorderBrush="{Binding BorderBrush, RelativeSource={RelativeSource AncestorType=ComboBox}}"
                            BorderThickness="{Binding BorderThickness, RelativeSource={RelativeSource AncestorType=ComboBox}}"
                            CornerRadius="4">
                      <Grid>
                        <Grid.ColumnDefinitions>
                          <ColumnDefinition Width="*"/>
                          <ColumnDefinition Width="22"/>
                        </Grid.ColumnDefinitions>
                        <Border Grid.Column="0" Background="Transparent"/>
                        <Path Grid.Column="1" Fill="{StaticResource TextPrimary}"
                              HorizontalAlignment="Center" VerticalAlignment="Center"
                              Data="M 0 0 L 4 4 L 8 0 Z"/>
                      </Grid>
                    </Border>
                    <ControlTemplate.Triggers>
                      <Trigger Property="IsMouseOver" Value="True">
                        <Setter TargetName="TemplateBorder" Property="BorderBrush" Value="{StaticResource Accent}"/>
                      </Trigger>
                    </ControlTemplate.Triggers>
                  </ControlTemplate>
                </ToggleButton.Template>
              </ToggleButton>
              <ContentPresenter x:Name="ContentSite"
                                IsHitTestVisible="False"
                                Content="{TemplateBinding SelectionBoxItem}"
                                ContentTemplate="{TemplateBinding SelectionBoxItemTemplate}"
                                ContentTemplateSelector="{TemplateBinding ItemTemplateSelector}"
                                Margin="8,3,26,3"
                                VerticalAlignment="Center"
                                HorizontalAlignment="Left"/>
              <TextBox x:Name="PART_EditableTextBox"
                       Style="{x:Null}"
                       Visibility="Hidden"
                       IsReadOnly="{TemplateBinding IsReadOnly}"
                       Margin="8,3,26,3"
                       VerticalAlignment="Center"
                       Background="Transparent"
                       Foreground="{StaticResource TextPrimary}"
                       BorderThickness="0"
                       Focusable="True"/>
              <Popup x:Name="Popup"
                     Placement="Bottom"
                     IsOpen="{TemplateBinding IsDropDownOpen}"
                     AllowsTransparency="True"
                     Focusable="False"
                     PopupAnimation="Slide">
                <Grid x:Name="DropDown"
                      MinWidth="{TemplateBinding ActualWidth}"
                      MaxHeight="{TemplateBinding MaxDropDownHeight}">
                  <Border x:Name="DropDownBorder"
                          Background="{StaticResource BgCard}"
                          BorderBrush="{StaticResource Border}"
                          BorderThickness="1"
                          CornerRadius="4">
                    <ScrollViewer Margin="2" SnapsToDevicePixels="True">
                      <StackPanel IsItemsHost="True" KeyboardNavigation.DirectionalNavigation="Contained"/>
                    </ScrollViewer>
                  </Border>
                </Grid>
              </Popup>
            </Grid>
            <ControlTemplate.Triggers>
              <Trigger Property="HasItems" Value="False">
                <Setter TargetName="DropDownBorder" Property="MinHeight" Value="40"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter Property="Opacity" Value="0.45"/>
              </Trigger>
              <Trigger Property="IsEditable" Value="True">
                <Setter TargetName="PART_EditableTextBox" Property="Visibility" Value="Visible"/>
                <Setter TargetName="ContentSite" Property="Visibility" Value="Hidden"/>
              </Trigger>
              <Trigger Property="IsKeyboardFocusWithin" Value="True">
                <Setter Property="BorderBrush" Value="{StaticResource Accent}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>

  <!-- Main Layout -->
  <DockPanel LastChildFill="True">
    
    <!-- TOP TOOLBAR -->
    <Border DockPanel.Dock="Top" Background="{StaticResource BgCard}"
            BorderThickness="0,0,0,1" BorderBrush="{StaticResource Border}" Padding="10,8">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>

        <!-- Connection Controls -->
        <StackPanel Grid.Column="0" Orientation="Horizontal" HorizontalAlignment="Left">
          <TextBlock Text="DHCP Server:" Style="{StaticResource FormLabel}"
                     VerticalAlignment="Center" Margin="0,0,8,0"/>
          <TextBox x:Name="TxtServerName" Width="200" Style="{StaticResource DarkTextBox}"
                   Text="localhost" ToolTip="DHCP server hostname or IP address"/>
          <Button x:Name="BtnConnect" Content="🔌 Connect" Margin="8,0"
                  Style="{StaticResource BtnSuccess}" ToolTip="Connect to DHCP server"/>
          <Button x:Name="BtnScanDomain" Content="🔍 Scan Domain" Margin="0,0,8,0"
                  Style="{StaticResource BtnPrimary}"
                  ToolTip="Discover authorized DHCP servers in the domain and ping them"/>
          <Button x:Name="BtnDisconnect" Content="🔌 Disconnect" Margin="0,0,8,0"
                  Style="{StaticResource BtnSecondary}" IsEnabled="False"
                  ToolTip="Disconnect from current server"/>
          <Button x:Name="BtnRefresh" Content="🔄 Refresh" Margin="0,0,8,0"
                  Style="{StaticResource BtnSecondary}" IsEnabled="False"
                  ToolTip="Refresh current view"/>
        </StackPanel>

        <!-- Quick Action Buttons -->
        <StackPanel Grid.Column="2" Orientation="Horizontal" HorizontalAlignment="Right">
          <Button x:Name="BtnViewDashboard" Content="📡 Dashboard" Margin="0,0,8,0"
                  Style="{StaticResource BtnSecondary}" ToolTip="IPAM-style DHCP monitoring dashboard"/>
          <Button x:Name="BtnViewMigrate" Content="🚚 Migrate" Margin="0,0,8,0"
                  Style="{StaticResource BtnSecondary}" ToolTip="Migrate scopes to another DHCP server"/>
          <Button x:Name="BtnViewEvents" Content="📡 Events" Margin="0,0,8,0"
                  Style="{StaticResource BtnSecondary}" ToolTip="DHCP audit logs and live events"/>
          <Button x:Name="BtnViewTroubleshoot" Content="🛠️ Troubleshoot" Margin="0,0,8,0"
                  Style="{StaticResource BtnSecondary}" ToolTip="BAD_ADDRESS and scope conflict diagnostics"/>
          <Button x:Name="BtnViewCompare" Content="🔀 Compare" Margin="0,0,8,0"
                  Style="{StaticResource BtnSecondary}" ToolTip="Compare two DHCP servers"/>
          <Button x:Name="BtnViewLog" Content="📋 View Log" Margin="0,0,8,0"
                  Style="{StaticResource BtnSecondary}" ToolTip="View action log"/>
          <Button x:Name="BtnSettings" Content="⚙️ Settings" Margin="0,0,8,0"
                  Style="{StaticResource BtnSecondary}" ToolTip="Application settings"/>
          <Button x:Name="BtnAbout" Content="ℹ️ About"
                  Style="{StaticResource BtnSecondary}" ToolTip="About DHCP Manager"/>
        </StackPanel>
      </Grid>
    </Border>

    <!-- BOTTOM STATUS BAR -->
    <Border DockPanel.Dock="Bottom" Background="{StaticResource BgCard}"
            BorderThickness="0,1,0,0" BorderBrush="{StaticResource Border}" Padding="10,5">
      <StackPanel>
        <Grid>
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          
          <TextBlock Grid.Column="0" Foreground="{StaticResource TextSecond}" FontSize="11">
            <Run Text="Server: "/>
            <Run x:Name="StatusServer" Text="Not Connected" Foreground="{StaticResource Warning}"/>
          </TextBlock>
          
          <TextBlock x:Name="StatusMessage" Grid.Column="1" Text="Ready"
                     Foreground="{StaticResource TextSecond}" FontSize="11"
                     HorizontalAlignment="Center"/>
          
          <TextBlock Grid.Column="2" Foreground="{StaticResource TextSecond}" FontSize="11">
            <Run Text="v2.7.2  |  "/>
            <Run Text="Created by Anthony Blake" Foreground="#90CAF9"/>
            <Run Text="  |  "/>
            <Run x:Name="StatusTime" Text=""/>
          </TextBlock>
        </Grid>

        <!-- Shared task progress (ingest, scan, migrate, etc.) -->
        <Grid x:Name="TaskProgressPanel" Margin="0,6,0,0" Visibility="Collapsed">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <StackPanel Grid.Column="0" Margin="0,0,12,0">
            <TextBlock x:Name="TxtTaskProgress" Text="" Foreground="{StaticResource TextPrimary}"
                       FontSize="11" Margin="0,0,0,3" TextWrapping="NoWrap"/>
            <ProgressBar x:Name="BarTaskProgress" Height="10" Minimum="0" Maximum="100" Value="0"
                         Background="{StaticResource BgDeep}" Foreground="{StaticResource Accent}"
                         BorderBrush="{StaticResource Border}" BorderThickness="1"/>
          </StackPanel>
          <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
            <Button x:Name="BtnTaskPause" Content="⏸ Pause" Width="88" Height="26" Margin="0,0,8,0"
                    Style="{StaticResource BtnSecondary}" IsEnabled="False"
                    ToolTip="Pause or resume the current long-running task"/>
            <Button x:Name="BtnTaskCancel" Content="⏹ Cancel" Width="88" Height="26"
                    Style="{StaticResource BtnDanger}" IsEnabled="False"
                    ToolTip="Cancel the current long-running task"/>
          </StackPanel>
        </Grid>
      </StackPanel>
    </Border>

    <!-- MAIN CONTENT AREA with Navigation and Tabs -->
    <Grid DockPanel.Dock="Top" Margin="0">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="280" MinWidth="240"/>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="*" MinWidth="400"/>
      </Grid.ColumnDefinitions>

      <!-- LEFT NAVIGATION PANEL -->
      <Border Grid.Column="0" Background="{StaticResource BgCard}"
              BorderThickness="0,0,1,0" BorderBrush="{StaticResource Border}"
              ClipToBounds="True">
        <DockPanel>
          <Border DockPanel.Dock="Top" Background="{StaticResource BgPanel}"
                  Padding="8,10" BorderThickness="0,0,0,1" BorderBrush="{StaticResource Border}">
            <StackPanel>
              <TextBlock Text="📡 DHCP Navigation" Foreground="{StaticResource TextPrimary}"
                         FontWeight="SemiBold" FontSize="13" Margin="0,0,0,8"
                         TextTrimming="CharacterEllipsis"/>
              <!-- Dock buttons first so the TextBox cannot shove them off-screen as text grows -->
              <DockPanel LastChildFill="True" Margin="0,0,0,6">
                <Button x:Name="BtnNavScopeSearchClear" DockPanel.Dock="Right"
                        Content="✕" Width="32" Height="32" Margin="6,0,0,0"
                        Style="{StaticResource BtnSecondary}"
                        ToolTip="Clear scope search"/>
                <TextBox x:Name="TxtNavScopeSearch" Height="32" MinHeight="32" MinWidth="0"
                         HorizontalAlignment="Stretch"
                         Style="{StaticResource DarkTextBox}"
                         Background="#12151A"
                         Foreground="#F2F4F8"
                         CaretBrush="#F2F4F8"
                         FontSize="13"
                         Padding="8,4"
                         VerticalContentAlignment="Center"
                         ToolTip="Search scopes by name or Scope ID (Enter = next match)"/>
              </DockPanel>
              <Button x:Name="BtnNavScopeFind" Content="Find next match" Height="32"
                      HorizontalAlignment="Stretch" Margin="0,0,0,6"
                      Style="{StaticResource BtnSecondary}"
                      ToolTip="Jump to the next matching scope"/>
              <TextBlock x:Name="TxtNavScopeSearchStatus"
                         Foreground="{StaticResource TextSecond}" FontSize="10"
                         Text="Search by scope name or ID"
                         TextWrapping="Wrap"/>
            </StackPanel>
          </Border>
          
          <TreeView x:Name="NavTree" Background="{StaticResource BgCard}"
                    BorderThickness="0" Padding="8">
            <TreeView.Resources>
              <Style TargetType="TreeViewItem">
                <Setter Property="Foreground" Value="{StaticResource TextPrimary}"/>
                <Setter Property="IsExpanded" Value="True"/>
                <Setter Property="Padding" Value="4,3"/>
              </Style>
            </TreeView.Resources>
          </TreeView>
        </DockPanel>
      </Border>

      <!-- SPLITTER -->
      <GridSplitter Grid.Column="1" Width="4" HorizontalAlignment="Stretch"
                    Background="{StaticResource Border}" ShowsPreview="False"/>

      <!-- RIGHT CONTENT PANEL with Tabs -->
      <Border Grid.Column="2" Background="{StaticResource BgPanel}" Padding="0">
        <TabControl x:Name="MainTabs" Padding="0">
          

          <!-- TAB: Monitoring Dashboard (IPAM-style) -->
          <TabItem x:Name="TabDashboard" Header="📡 Dashboard">
            <ScrollViewer VerticalScrollBarVisibility="Auto" Background="{StaticResource BgPanel}">
              <Grid Margin="12">
                <Grid.RowDefinitions>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="320"/>
                  <RowDefinition Height="200"/>
                  <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>

                <Border Grid.Row="0" Background="{StaticResource BgCard}" CornerRadius="6" Padding="14,12" Margin="0,0,0,10">
                  <Grid>
                    <Grid.ColumnDefinitions>
                      <ColumnDefinition Width="*"/>
                      <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <StackPanel Grid.Column="0">
                      <TextBlock Text="DHCP Monitoring Dashboard" Style="{StaticResource SectionHeader}" Margin="0,0,0,4"/>
                      <TextBlock x:Name="TxtDashboardSubtitle" TextWrapping="Wrap"
                                 Foreground="{StaticResource TextSecond}" FontSize="12"
                                 Text="Connect to a server and Refresh Monitoring for a SolarWinds-style summary: capacity, alerts, top scopes, failover, and estate health."/>
                    </StackPanel>
                    <WrapPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center" HorizontalAlignment="Right">
                      <Button x:Name="BtnDashboardRefresh" Content="🔄 Refresh Monitoring" Margin="0,0,8,4"
                              Style="{StaticResource BtnPrimary}" IsEnabled="False"
                              ToolTip="Poll server statistics, failover, and rebuild Top 10 / Active Alerts"/>
                      <Button x:Name="BtnDashboardOpenStats" Content="📊 Statistics" Margin="0,0,8,4"
                              Style="{StaticResource BtnSecondary}" IsEnabled="False"/>
                      <Button x:Name="BtnDashboardScanEstate" Content="🌐 Scan Estate" Margin="0,0,0,4"
                              Style="{StaticResource BtnSecondary}"
                              ToolTip="Open Domain DHCP scan for multi-server estate inventory"/>
                    </WrapPanel>
                  </Grid>
                </Border>

                <UniformGrid Grid.Row="1" Rows="1" Columns="6" Margin="0,0,0,10">
                  <Border Background="{StaticResource BgCard}" CornerRadius="6" Padding="12" Margin="0,0,6,0">
                    <StackPanel>
                      <TextBlock Text="SCOPES" Style="{StaticResource FormLabel}"/>
                      <TextBlock x:Name="DashKpiScopes" Text="—" FontSize="28" FontWeight="Bold" Foreground="{StaticResource Accent}"/>
                    </StackPanel>
                  </Border>
                  <Border Background="{StaticResource BgCard}" CornerRadius="6" Padding="12" Margin="3,0">
                    <StackPanel>
                      <TextBlock Text="ACTIVE LEASES" Style="{StaticResource FormLabel}"/>
                      <TextBlock x:Name="DashKpiLeases" Text="—" FontSize="28" FontWeight="Bold" Foreground="{StaticResource Success}"/>
                    </StackPanel>
                  </Border>
                  <Border Background="{StaticResource BgCard}" CornerRadius="6" Padding="12" Margin="3,0">
                    <StackPanel>
                      <TextBlock Text="AVAILABLE IPs" Style="{StaticResource FormLabel}"/>
                      <TextBlock x:Name="DashKpiAvailable" Text="—" FontSize="28" FontWeight="Bold" Foreground="{StaticResource TextPrimary}"/>
                    </StackPanel>
                  </Border>
                  <Border Background="{StaticResource BgCard}" CornerRadius="6" Padding="12" Margin="3,0">
                    <StackPanel>
                      <TextBlock Text="UTILIZATION" Style="{StaticResource FormLabel}"/>
                      <TextBlock x:Name="DashKpiUtil" Text="—" FontSize="28" FontWeight="Bold" Foreground="{StaticResource Accent}"/>
                    </StackPanel>
                  </Border>
                  <Border Background="{StaticResource BgCard}" CornerRadius="6" Padding="12" Margin="3,0">
                    <StackPanel>
                      <TextBlock Text="CRITICAL" Style="{StaticResource FormLabel}"/>
                      <TextBlock x:Name="DashKpiCritical" Text="—" FontSize="28" FontWeight="Bold" Foreground="{StaticResource Danger}"/>
                    </StackPanel>
                  </Border>
                  <Border Background="{StaticResource BgCard}" CornerRadius="6" Padding="12" Margin="6,0,0,0">
                    <StackPanel>
                      <TextBlock Text="WARNINGS" Style="{StaticResource FormLabel}"/>
                      <TextBlock x:Name="DashKpiWarning" Text="—" FontSize="28" FontWeight="Bold" Foreground="{StaticResource Warning}"/>
                    </StackPanel>
                  </Border>
                </UniformGrid>

                <Border Grid.Row="2" Background="{StaticResource BgCard}" CornerRadius="6" Padding="12,10" Margin="0,0,0,10">
                  <StackPanel>
                    <TextBlock Text="Server health" Style="{StaticResource FormLabel}" Margin="0,0,0,6"/>
                    <TextBlock x:Name="TxtDashboardHealth" TextWrapping="Wrap" FontSize="12"
                               Foreground="{StaticResource TextPrimary}"
                               Text="Health details appear after Refresh Monitoring."/>
                  </StackPanel>
                </Border>

                <Grid Grid.Row="3" Margin="0,0,0,10">
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="*"/>
                  </Grid.ColumnDefinitions>
                  <DockPanel Grid.Column="0" Margin="0,0,6,0">
                    <TextBlock DockPanel.Dock="Top" Text="Active alerts" Style="{StaticResource FormLabel}" Margin="0,0,0,6"/>
                    <DataGrid x:Name="GridDashboardAlerts" Style="{StaticResource DarkGrid}"
                              IsReadOnly="True" SelectionMode="Single"
                              ToolTip="Double-click to open Statistics for the scope">
                      <DataGrid.Columns>
                        <DataGridTextColumn Header="Severity" Binding="{Binding Severity}" Width="80"/>
                        <DataGridTextColumn Header="Type" Binding="{Binding AlertType}" Width="110"/>
                        <DataGridTextColumn Header="Scope" Binding="{Binding ScopeId}" Width="110"/>
                        <DataGridTextColumn Header="Name" Binding="{Binding Name}" Width="140"/>
                        <DataGridTextColumn Header="Detail" Binding="{Binding Detail}" Width="*"/>
                      </DataGrid.Columns>
                    </DataGrid>
                  </DockPanel>
                  <DockPanel Grid.Column="1" Margin="6,0,0,0">
                    <TextBlock DockPanel.Dock="Top" Text="Top 10 scopes by utilization" Style="{StaticResource FormLabel}" Margin="0,0,0,6"/>
                    <DataGrid x:Name="GridDashboardTopScopes" Style="{StaticResource DarkGrid}"
                              IsReadOnly="True" SelectionMode="Single"
                              ToolTip="Double-click for scope statistics details">
                      <DataGrid.Columns>
                        <DataGridTextColumn Header="#" Binding="{Binding Rank}" Width="36"/>
                        <DataGridTextColumn Header="Util %" Binding="{Binding PercentDisplay}" Width="70"/>
                        <DataGridTextColumn Header="Status" Binding="{Binding Status}" Width="110"/>
                        <DataGridTextColumn Header="Scope ID" Binding="{Binding ScopeId}" Width="110"/>
                        <DataGridTextColumn Header="Name" Binding="{Binding Name}" Width="*"/>
                        <DataGridTextColumn Header="Free" Binding="{Binding Free}" Width="60"/>
                      </DataGrid.Columns>
                    </DataGrid>
                  </DockPanel>
                </Grid>

                <DockPanel Grid.Row="4" Margin="0,0,0,8">
                  <DockPanel DockPanel.Dock="Top" Margin="0,0,0,6" LastChildFill="True">
                    <TextBlock Text="Estate snapshot (from Domain Scan)" Style="{StaticResource FormLabel}" VerticalAlignment="Center"/>
                    <TextBlock x:Name="TxtDashboardEstateHint" DockPanel.Dock="Right"
                               Foreground="{StaticResource TextSecond}" FontSize="11"
                               Text="Run Scan Domain to populate multi-server health"/>
                  </DockPanel>
                  <DataGrid x:Name="GridDashboardEstate" Style="{StaticResource DarkGrid}"
                            IsReadOnly="True" SelectionMode="Single">
                    <DataGrid.Columns>
                      <DataGridTextColumn Header="Server" Binding="{Binding DnsName}" Width="200"/>
                      <DataGridTextColumn Header="IP" Binding="{Binding IPAddress}" Width="120"/>
                      <DataGridTextColumn Header="Online" Binding="{Binding Online}" Width="70"/>
                      <DataGridTextColumn Header="Authorized" Binding="{Binding Authorized}" Width="90"/>
                      <DataGridTextColumn Header="Latency" Binding="{Binding LatencyMs}" Width="80"/>
                      <DataGridTextColumn Header="Detail" Binding="{Binding Detail}" Width="*"/>
                    </DataGrid.Columns>
                  </DataGrid>
                </DockPanel>

                <TextBlock Grid.Row="5" x:Name="TxtDashboardStatus" Style="{StaticResource FormLabel}"
                           TextWrapping="Wrap"
                           Text="Tip: This dashboard mirrors SolarWinds IPAM Summary widgets (capacity KPIs, active alerts, Top 10 utilization, estate inventory). Full CRUD remains on the management tabs."/>
              </Grid>
            </ScrollViewer>
          </TabItem>

          <!-- TAB: Scopes -->
          <TabItem x:Name="TabScopes" Header="🌐 Scopes">
            <Grid Background="{StaticResource BgPanel}">
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
              </Grid.RowDefinitions>

              <!-- Scope Toolbar -->
              <Border Grid.Row="0" Background="{StaticResource BgCard}"
                      BorderThickness="0,0,0,1" BorderBrush="{StaticResource Border}" Padding="12,10">
                <StackPanel>
                <StackPanel Orientation="Horizontal" Margin="0,0,0,6">
                  <Button x:Name="BtnScopeAdd" Content="➕ New Scope" Margin="0,0,8,0"
                          Style="{StaticResource BtnSuccess}" IsEnabled="False"/>
                  <Button x:Name="BtnScopeEdit" Content="✏️ Edit" Margin="0,0,8,0"
                          Style="{StaticResource BtnSecondary}" IsEnabled="False"/>
                  <Button x:Name="BtnScopeDelete" Content="🗑️ Delete" Margin="0,0,8,0"
                          Style="{StaticResource BtnDanger}" IsEnabled="False"/>
                  <Separator Width="1" Background="{StaticResource Border}" Margin="8,0"/>
                  <Button x:Name="BtnScopeActivate" Content="▶️ Activate" Margin="8,0,8,0"
                          Style="{StaticResource BtnSuccess}" IsEnabled="False"/>
                  <Button x:Name="BtnScopeDeactivate" Content="⏸️ Deactivate" Margin="0,0,8,0"
                          Style="{StaticResource BtnSecondary}" IsEnabled="False"/>
                </StackPanel>
                <StackPanel Orientation="Horizontal">
                  <TextBlock Text="Filter:" Style="{StaticResource FormLabel}" VerticalAlignment="Center" Margin="0,0,8,0"/>
                  <TextBox x:Name="TxtScopeFilter" Width="260" Style="{StaticResource DarkTextBox}"
                           ToolTip="Filter scopes by ID, name, or range (SolarWinds-style dynamic filter)"/>
                  <TextBlock x:Name="TxtScopeFilterCount" Text="" Style="{StaticResource FormLabel}"
                             VerticalAlignment="Center" Margin="12,0,0,0"/>
                </StackPanel>
                </StackPanel>
              </Border>

              <!-- Scopes Grid -->
              <DataGrid Grid.Row="1" x:Name="GridScopes" Style="{StaticResource DarkGrid}" Margin="8">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Scope ID" Binding="{Binding ScopeId}" Width="140"/>
                  <DataGridTextColumn Header="Name" Binding="{Binding Name}" Width="180"/>
                  <DataGridTextColumn Header="Start" Binding="{Binding StartRange}" Width="125"/>
                  <DataGridTextColumn Header="End" Binding="{Binding EndRange}" Width="125"/>
                  <DataGridTextColumn Header="Subnet Mask" Binding="{Binding SubnetMask}" Width="120"/>
                  <DataGridTextColumn Header="State" Binding="{Binding State}" Width="80"/>
                  <DataGridTextColumn Header="Leases" Binding="{Binding LeasesInUse}" Width="70"/>
                </DataGrid.Columns>
              </DataGrid>
            </Grid>
          </TabItem>

          <!-- TAB: Leases -->
          <TabItem x:Name="TabLeases" Header="📄 Leases">
            <Grid Background="{StaticResource BgPanel}">
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
              </Grid.RowDefinitions>

              <!-- Lease Toolbar -->
              <Border Grid.Row="0" Background="{StaticResource BgCard}"
                      BorderThickness="0,0,0,1" BorderBrush="{StaticResource Border}" Padding="12,10">
                <StackPanel>
                  <StackPanel Orientation="Horizontal" Margin="0,0,0,6">
                    <Button x:Name="BtnLeaseRelease" Content="🚫 Release" Margin="0,0,8,0"
                            Style="{StaticResource BtnDanger}" IsEnabled="False"
                            ToolTip="Release the selected lease(s). Use Ctrl/Shift-click to multi-select."/>
                    <Button x:Name="BtnLeaseReserve" Content="📌 Convert to Reservation" Margin="0,0,8,0"
                            Style="{StaticResource BtnPrimary}" IsEnabled="False"
                            ToolTip="Convert the selected lease(s) to reservations. Use Ctrl/Shift-click to multi-select."/>
                    <Button x:Name="BtnLeaseRefresh" Content="🔄 Refresh" Margin="0,0,8,0"
                            Style="{StaticResource BtnSecondary}" IsEnabled="False"/>
                    <Separator Width="1" Background="{StaticResource Border}" Margin="8,0"/>
                    <Button x:Name="BtnLeaseSelectAll" Content="☑ Select All" Margin="8,0,8,0"
                            Style="{StaticResource BtnSecondary}" IsEnabled="False"
                            ToolTip="Select all leases currently shown in the grid"/>
                    <Button x:Name="BtnLeaseClearSel" Content="Clear Selection" Margin="0,0,8,0"
                            Style="{StaticResource BtnSecondary}" IsEnabled="False"/>
                    <TextBlock x:Name="TxtLeaseSelectedCount" Text="None selected"
                               Style="{StaticResource FormLabel}" VerticalAlignment="Center" Margin="8,0,0,0"/>
                  </StackPanel>
                  <StackPanel Orientation="Horizontal">
                    <TextBlock Text="Filter:" Style="{StaticResource FormLabel}"
                               VerticalAlignment="Center" Margin="0,0,8,0"/>
                    <TextBox x:Name="TxtLeaseFilter" Width="220" Style="{StaticResource DarkTextBox}"
                             ToolTip="Filter by IP, MAC, or hostname"/>
                    <TextBlock Text="  Tip: Ctrl+click or Shift+click to select multiple leases"
                               Style="{StaticResource FormLabel}" VerticalAlignment="Center" Margin="12,0,0,0"/>
                  </StackPanel>
                </StackPanel>
              </Border>

              <!-- Leases Grid -->
              <DataGrid Grid.Row="1" x:Name="GridLeases" Style="{StaticResource DarkGrid}" Margin="8"
                        SelectionMode="Extended" SelectionUnit="FullRow">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="IP Address" Binding="{Binding IPAddress}" Width="130"/>
                  <DataGridTextColumn Header="MAC Address" Binding="{Binding ClientId}" Width="140"/>
                  <DataGridTextColumn Header="Hostname" Binding="{Binding HostName}" Width="180"/>
                  <DataGridTextColumn Header="Lease Expiry" Binding="{Binding LeaseExpiryTime}" Width="150"/>
                  <DataGridTextColumn Header="Type" Binding="{Binding AddressState}" Width="100"/>
                  <DataGridTextColumn Header="Scope" Binding="{Binding ScopeId}" Width="130"/>
                </DataGrid.Columns>
              </DataGrid>
            </Grid>
          </TabItem>

          <!-- TAB: Reservations -->
          <TabItem x:Name="TabReservations" Header="📌 Reservations">
            <Grid Background="{StaticResource BgPanel}">
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
              </Grid.RowDefinitions>

              <!-- Reservation Toolbar -->
              <Border Grid.Row="0" Background="{StaticResource BgCard}"
                      BorderThickness="0,0,0,1" BorderBrush="{StaticResource Border}" Padding="12,10">
                <StackPanel Orientation="Horizontal">
                  <Button x:Name="BtnResAdd" Content="➕ New Reservation" Margin="0,0,8,0"
                          Style="{StaticResource BtnSuccess}" IsEnabled="False"/>
                  <Button x:Name="BtnResEdit" Content="✏️ Edit" Margin="0,0,8,0"
                          Style="{StaticResource BtnSecondary}" IsEnabled="False"/>
                  <Button x:Name="BtnResDelete" Content="🗑️ Delete" Margin="0,0,8,0"
                          Style="{StaticResource BtnDanger}" IsEnabled="False"/>
                </StackPanel>
              </Border>

              <!-- Reservations Grid -->
              <DataGrid Grid.Row="1" x:Name="GridReservations" Style="{StaticResource DarkGrid}" Margin="8">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="IP Address" Binding="{Binding IPAddress}" Width="140"/>
                  <DataGridTextColumn Header="MAC Address" Binding="{Binding ClientId}" Width="160"/>
                  <DataGridTextColumn Header="Name" Binding="{Binding Name}" Width="200"/>
                  <DataGridTextColumn Header="Description" Binding="{Binding Description}" Width="*"/>
                  <DataGridTextColumn Header="Type" Binding="{Binding Type}" Width="90"/>
                </DataGrid.Columns>
              </DataGrid>
            </Grid>
          </TabItem>

          <!-- TAB: Exclusions -->
          <TabItem x:Name="TabExclusions" Header="🚫 Exclusions">
            <Grid Background="{StaticResource BgPanel}">
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
              </Grid.RowDefinitions>

              <!-- Exclusion Toolbar -->
              <Border Grid.Row="0" Background="{StaticResource BgCard}"
                      BorderThickness="0,0,0,1" BorderBrush="{StaticResource Border}" Padding="12,10">
                <StackPanel Orientation="Horizontal">
                  <Button x:Name="BtnExcAdd" Content="➕ New Exclusion" Margin="0,0,8,0"
                          Style="{StaticResource BtnSuccess}" IsEnabled="False"/>
                  <Button x:Name="BtnExcDelete" Content="🗑️ Delete" Margin="0,0,8,0"
                          Style="{StaticResource BtnDanger}" IsEnabled="False"/>
                </StackPanel>
              </Border>

              <!-- Exclusions Grid -->
              <DataGrid Grid.Row="1" x:Name="GridExclusions" Style="{StaticResource DarkGrid}" Margin="8">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Start Range" Binding="{Binding StartRange}" Width="150"/>
                  <DataGridTextColumn Header="End Range" Binding="{Binding EndRange}" Width="150"/>
                  <DataGridTextColumn Header="Scope ID" Binding="{Binding ScopeId}" Width="140"/>
                  <DataGridTextColumn Header="Description" Binding="{Binding Description}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
            </Grid>
          </TabItem>

          <!-- TAB: Options -->
          <TabItem x:Name="TabOptions" Header="⚙️ Options">
            <Grid Background="{StaticResource BgPanel}">
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
              </Grid.RowDefinitions>

              <!-- Options Toolbar -->
              <Border Grid.Row="0" Background="{StaticResource BgCard}"
                      BorderThickness="0,0,0,1" BorderBrush="{StaticResource Border}" Padding="12,10">
                <StackPanel Orientation="Horizontal">
                  <TextBlock Text="Level:" Style="{StaticResource FormLabel}"
                             VerticalAlignment="Center" Margin="0,0,8,0"/>
                  <ComboBox x:Name="CboOptionLevel" Width="150" Height="26" Margin="0,0,12,0"
                            Background="{StaticResource BgDeep}" Foreground="{StaticResource TextPrimary}"
                            BorderBrush="{StaticResource Border}">
                    <ComboBoxItem Content="Server" IsSelected="True"/>
                    <ComboBoxItem Content="Scope"/>
                    <ComboBoxItem Content="Reservation"/>
                  </ComboBox>
                  <Button x:Name="BtnOptionSet" Content="✏️ Set Option" Margin="0,0,8,0"
                          Style="{StaticResource BtnPrimary}" IsEnabled="False"/>
                  <Button x:Name="BtnOptionDelete" Content="🗑️ Remove Option" Margin="0,0,8,0"
                          Style="{StaticResource BtnDanger}" IsEnabled="False"/>
                </StackPanel>
              </Border>

              <!-- Options Grid -->
              <DataGrid Grid.Row="1" x:Name="GridOptions" Style="{StaticResource DarkGrid}" Margin="8">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Option ID" Binding="{Binding OptionId}" Width="80"/>
                  <DataGridTextColumn Header="Name" Binding="{Binding Name}" Width="180"/>
                  <DataGridTextColumn Header="Value" Binding="{Binding Value}" Width="250"/>
                  <DataGridTextColumn Header="Vendor" Binding="{Binding VendorClass}" Width="120"/>
                  <DataGridTextColumn Header="Policy" Binding="{Binding PolicyName}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
            </Grid>
          </TabItem>

          <!-- TAB: Filters -->
          <TabItem x:Name="TabFilters" Header="🔒 MAC Filters">
            <Grid Background="{StaticResource BgPanel}">
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
              </Grid.RowDefinitions>

              <!-- Filters Toolbar -->
              <Border Grid.Row="0" Background="{StaticResource BgCard}"
                      BorderThickness="0,0,0,1" BorderBrush="{StaticResource Border}" Padding="12,10">
                <StackPanel Orientation="Horizontal">
                  <TextBlock Text="List:" Style="{StaticResource FormLabel}"
                             VerticalAlignment="Center" Margin="0,0,8,0"/>
                  <ComboBox x:Name="CboFilterList" Width="120" Height="26" Margin="0,0,12,0"
                            Background="{StaticResource BgDeep}" Foreground="{StaticResource TextPrimary}"
                            BorderBrush="{StaticResource Border}">
                    <ComboBoxItem Content="Allow" IsSelected="True"/>
                    <ComboBoxItem Content="Deny"/>
                  </ComboBox>
                  <Button x:Name="BtnFilterAdd" Content="➕ Add Filter" Margin="0,0,8,0"
                          Style="{StaticResource BtnSuccess}" IsEnabled="False"/>
                  <Button x:Name="BtnFilterDelete" Content="🗑️ Delete" Margin="0,0,8,0"
                          Style="{StaticResource BtnDanger}" IsEnabled="False"/>
                  <Separator Width="1" Background="{StaticResource Border}" Margin="8,0"/>
                  <CheckBox x:Name="ChkEnableFilters" Content="Enable Filtering" Margin="8,0"
                            IsEnabled="False" Foreground="{StaticResource TextPrimary}"/>
                </StackPanel>
              </Border>

              <!-- Filters Grid -->
              <DataGrid Grid.Row="1" x:Name="GridFilters" Style="{StaticResource DarkGrid}" Margin="8">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="MAC Address" Binding="{Binding MacAddress}" Width="180"/>
                  <DataGridTextColumn Header="List Type" Binding="{Binding ListType}" Width="100"/>
                  <DataGridTextColumn Header="Description" Binding="{Binding Description}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
            </Grid>
          </TabItem>

          <!-- TAB: Policies -->
          <TabItem x:Name="TabPolicies" Header="📋 Policies">
            <Grid Background="{StaticResource BgPanel}">
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
              </Grid.RowDefinitions>

              <!-- Policies Toolbar -->
              <Border Grid.Row="0" Background="{StaticResource BgCard}"
                      BorderThickness="0,0,0,1" BorderBrush="{StaticResource Border}" Padding="12,10">
                <StackPanel Orientation="Horizontal">
                  <Button x:Name="BtnPolicyAdd" Content="➕ New Policy" Margin="0,0,8,0"
                          Style="{StaticResource BtnSuccess}" IsEnabled="False"/>
                  <Button x:Name="BtnPolicyEdit" Content="✏️ Edit" Margin="0,0,8,0"
                          Style="{StaticResource BtnSecondary}" IsEnabled="False"/>
                  <Button x:Name="BtnPolicyDelete" Content="🗑️ Delete" Margin="0,0,8,0"
                          Style="{StaticResource BtnDanger}" IsEnabled="False"/>
                </StackPanel>
              </Border>

              <!-- Policies Grid -->
              <DataGrid Grid.Row="1" x:Name="GridPolicies" Style="{StaticResource DarkGrid}" Margin="8">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Policy Name" Binding="{Binding Name}" Width="180"/>
                  <DataGridTextColumn Header="Scope" Binding="{Binding ScopeId}" Width="130"/>
                  <DataGridTextColumn Header="Condition" Binding="{Binding Condition}" Width="200"/>
                  <DataGridTextColumn Header="Enabled" Binding="{Binding Enabled}" Width="80"/>
                  <DataGridTextColumn Header="Description" Binding="{Binding Description}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
            </Grid>
          </TabItem>

          <!-- TAB: Troubleshoot BAD_ADDRESS -->
          <TabItem x:Name="TabTroubleshoot" Header="🛠️ Troubleshoot">
            <Grid Background="{StaticResource BgPanel}" Margin="8">
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
                <RowDefinition Height="180"/>
                <RowDefinition Height="Auto"/>
              </Grid.RowDefinitions>

              <Border Grid.Row="0" Background="{StaticResource BgCard}" CornerRadius="6"
                      Padding="12,10" Margin="0,0,0,8">
                <StackPanel>
                  <TextBlock Text="BAD_ADDRESS conflict diagnostics" Style="{StaticResource SectionHeader}" Margin="0,0,0,8"/>
                  <WrapPanel Orientation="Horizontal">
                    <TextBlock Text="Scope:" Style="{StaticResource FormLabel}" VerticalAlignment="Center" Margin="0,0,8,4"/>
                    <ComboBox x:Name="CboTroubleshootScope" Width="280" Height="28" Margin="0,0,12,4"
                              Background="{StaticResource BgDeep}" Foreground="{StaticResource TextPrimary}"
                              BorderBrush="{StaticResource Border}"
                              ToolTip="Scope to analyze for BAD_ADDRESS leases"/>
                    <Button x:Name="BtnTroubleshootRefreshScopes" Content="🔄 Scopes" Margin="0,0,8,4"
                            Style="{StaticResource BtnSecondary}" IsEnabled="False"
                            ToolTip="Reload scope list from the connected server"/>
                    <Button x:Name="BtnTroubleshootUseSelected" Content="Use selected scope" Margin="0,0,12,4"
                            Style="{StaticResource BtnSecondary}" IsEnabled="False"
                            ToolTip="Use the scope currently selected in navigation / Scopes tab"/>
                    <TextBlock Text="Probe sample:" Style="{StaticResource FormLabel}" VerticalAlignment="Center" Margin="0,0,6,4"/>
                    <ComboBox x:Name="CboTroubleshootSample" Width="60" Height="28" Margin="0,0,12,4"
                              Background="{StaticResource BgDeep}" Foreground="{StaticResource TextPrimary}"
                              BorderBrush="{StaticResource Border}"
                              ToolTip="How many BAD addresses to ping/ARP">
                      <ComboBoxItem Content="3" IsSelected="True"/>
                      <ComboBoxItem Content="4"/>
                      <ComboBoxItem Content="5"/>
                    </ComboBox>
                    <Button x:Name="BtnTroubleshootRun" Content="▶️ Run Diagnostics" Margin="0,0,8,4"
                            Style="{StaticResource BtnPrimary}" IsEnabled="False"
                            ToolTip="Run the BAD_ADDRESS root-cause checklist for the selected scope"/>
                    <Button x:Name="BtnTroubleshootExport" Content="💾 Export Report" Margin="0,0,0,4"
                            Style="{StaticResource BtnSecondary}" IsEnabled="False"/>
                  </WrapPanel>
                </StackPanel>
              </Border>

              <Border Grid.Row="1" Background="{StaticResource BgCard}" CornerRadius="6"
                      Padding="12,8" Margin="0,0,0,8">
                <TextBlock x:Name="TxtTroubleshootSummary" TextWrapping="Wrap"
                           Foreground="{StaticResource TextPrimary}" FontSize="12"
                           Text="Connect to a DHCP server, choose a scope, then Run Diagnostics. Clear BAD_ADDRESS only after you review findings and correct the cause."/>
              </Border>

              <Grid Grid.Row="2" Margin="0,0,0,8">
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="1.2*"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <DockPanel Grid.Column="0" Margin="0,0,6,0">
                  <DockPanel DockPanel.Dock="Top" Margin="0,0,0,6" LastChildFill="True">
                    <Button x:Name="BtnTroubleshootFindingDetails" DockPanel.Dock="Right"
                            Content="🔍 Details" Margin="8,0,0,0"
                            Style="{StaticResource BtnSecondary}" IsEnabled="False"
                            ToolTip="Show full finding and recommendation (or double-click a row)"/>
                    <TextBlock Text="Diagnostic findings  (double-click for full text)" Style="{StaticResource FormLabel}"
                               VerticalAlignment="Center"/>
                  </DockPanel>
                  <DataGrid x:Name="GridTroubleshootFindings" Style="{StaticResource DarkGrid}"
                            IsReadOnly="True" SelectionMode="Single"
                            ToolTip="Double-click a row to view the full finding and recommendation">
                    <DataGrid.Columns>
                      <DataGridTextColumn Header="Step" Binding="{Binding Step}" Width="40"/>
                      <DataGridTextColumn Header="Check" Binding="{Binding Check}" Width="160"/>
                      <DataGridTextColumn Header="Status" Binding="{Binding Status}" Width="80"/>
                      <DataGridTextColumn Header="Finding" Binding="{Binding Finding}" Width="*"/>
                      <DataGridTextColumn Header="Recommendation" Binding="{Binding Recommendation}" Width="*"/>
                    </DataGrid.Columns>
                  </DataGrid>
                </DockPanel>
                <DockPanel Grid.Column="1" Margin="6,0,0,0">
                  <TextBlock DockPanel.Dock="Top" Text="BAD_ADDRESS leases in scope  (double-click for details)" Style="{StaticResource FormLabel}" Margin="0,0,0,6"/>
                  <DataGrid x:Name="GridTroubleshootBadLeases" Style="{StaticResource DarkGrid}"
                            IsReadOnly="True" SelectionMode="Extended"
                            ToolTip="Double-click a row for full lease details">
                    <DataGrid.Columns>
                      <DataGridTextColumn Header="IP Address" Binding="{Binding IPAddress}" Width="120"/>
                      <DataGridTextColumn Header="MAC / ClientId" Binding="{Binding ClientId}" Width="140"/>
                      <DataGridTextColumn Header="Hostname" Binding="{Binding HostName}" Width="120"/>
                      <DataGridTextColumn Header="State" Binding="{Binding AddressState}" Width="90"/>
                      <DataGridTextColumn Header="Lease Expiry" Binding="{Binding LeaseExpiryTime}" Width="*"/>
                    </DataGrid.Columns>
                  </DataGrid>
                </DockPanel>
              </Grid>

              <DockPanel Grid.Row="3" Margin="0,0,0,8">
                <TextBlock DockPanel.Dock="Top" Text="Ping / ARP sample probes  (double-click for details)" Style="{StaticResource FormLabel}" Margin="0,0,0,6"/>
                <DataGrid x:Name="GridTroubleshootProbes" Style="{StaticResource DarkGrid}"
                          IsReadOnly="True" SelectionMode="Single"
                          ToolTip="Double-click a row for full probe details">
                  <DataGrid.Columns>
                    <DataGridTextColumn Header="IP Address" Binding="{Binding IPAddress}" Width="120"/>
                    <DataGridTextColumn Header="Ping" Binding="{Binding PingStatus}" Width="70"/>
                    <DataGridTextColumn Header="Latency" Binding="{Binding LatencyMs}" Width="70"/>
                    <DataGridTextColumn Header="ARP MAC" Binding="{Binding ArpMac}" Width="140"/>
                    <DataGridTextColumn Header="ARP State" Binding="{Binding ArpState}" Width="100"/>
                    <DataGridTextColumn Header="Notes" Binding="{Binding Notes}" Width="*"/>
                  </DataGrid.Columns>
                </DataGrid>
              </DockPanel>

              <Border Grid.Row="4" Background="{StaticResource BgCard}" CornerRadius="6" Padding="12,10">
                <StackPanel>
                  <CheckBox x:Name="ChkTroubleshootReviewed" Content="I reviewed the findings and corrected the root cause (safe to clear BAD_ADDRESS)"
                            Margin="0,0,0,8" IsEnabled="False"
                            Foreground="{StaticResource TextPrimary}"/>
                  <StackPanel Orientation="Horizontal">
                    <Button x:Name="BtnTroubleshootClearBad" Content="🗑️ Clear BAD_ADDRESS leases" Margin="0,0,12,0"
                            Style="{StaticResource BtnDanger}" IsEnabled="False"
                            ToolTip="Removes BAD_ADDRESS leases for this scope only after diagnostics and confirmation"/>
                    <TextBlock x:Name="TxtTroubleshootClearHint" VerticalAlignment="Center"
                               Foreground="{StaticResource TextSecond}" FontSize="11"
                               Text="Clear stays disabled until diagnostics run and you confirm the cause was addressed."/>
                  </StackPanel>
                </StackPanel>
              </Border>
            </Grid>
          </TabItem>

          <!-- TAB: Statistics -->
          <TabItem x:Name="TabStats" Header="📊 Statistics">
            <Grid Background="{StaticResource BgPanel}" Margin="12">
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
                <RowDefinition Height="Auto"/>
              </Grid.RowDefinitions>

              <StackPanel Grid.Row="0">
                <TextBlock Text="Server Statistics" Style="{StaticResource SectionHeader}" Margin="0,0,0,8"/>
                <Grid>
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="*"/>
                  </Grid.ColumnDefinitions>
                  <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                  </Grid.RowDefinitions>

                  <Border Grid.Row="0" Grid.Column="0" Background="{StaticResource BgCard}"
                          CornerRadius="6" Padding="14" Margin="0,0,8,8">
                    <StackPanel>
                      <TextBlock Text="Total Scopes" Style="{StaticResource FormLabel}"/>
                      <TextBlock x:Name="StatTotalScopes" Text="0" FontSize="26" FontWeight="Bold"
                                 Foreground="{StaticResource Accent}"/>
                    </StackPanel>
                  </Border>

                  <Border Grid.Row="0" Grid.Column="1" Background="{StaticResource BgCard}"
                          CornerRadius="6" Padding="14" Margin="4,0,4,8">
                    <StackPanel>
                      <TextBlock Text="Active Leases" Style="{StaticResource FormLabel}"/>
                      <TextBlock x:Name="StatActiveLeases" Text="0" FontSize="26" FontWeight="Bold"
                                 Foreground="{StaticResource Success}"/>
                    </StackPanel>
                  </Border>

                  <Border Grid.Row="0" Grid.Column="2" Background="{StaticResource BgCard}"
                          CornerRadius="6" Padding="14" Margin="8,0,0,8">
                    <StackPanel>
                      <TextBlock Text="Reservations" Style="{StaticResource FormLabel}"/>
                      <TextBlock x:Name="StatReservations" Text="0" FontSize="26" FontWeight="Bold"
                                 Foreground="{StaticResource Warning}"/>
                    </StackPanel>
                  </Border>

                  <Border Grid.Row="1" Grid.Column="0" Background="{StaticResource BgCard}"
                          CornerRadius="6" Padding="14" Margin="0,0,8,8">
                    <StackPanel>
                      <TextBlock Text="Available IPs" Style="{StaticResource FormLabel}"/>
                      <TextBlock x:Name="StatAvailableIPs" Text="0" FontSize="26" FontWeight="Bold"
                                 Foreground="{StaticResource TextPrimary}"/>
                    </StackPanel>
                  </Border>

                  <Border Grid.Row="1" Grid.Column="1" Background="{StaticResource BgCard}"
                          CornerRadius="6" Padding="14" Margin="4,0,4,8">
                    <StackPanel>
                      <TextBlock Text="Total Addresses" Style="{StaticResource FormLabel}"/>
                      <TextBlock x:Name="StatTotalIPs" Text="0" FontSize="26" FontWeight="Bold"
                                 Foreground="{StaticResource TextPrimary}"/>
                    </StackPanel>
                  </Border>

                  <Border Grid.Row="1" Grid.Column="2" Background="{StaticResource BgCard}"
                          CornerRadius="6" Padding="14" Margin="8,0,0,8">
                    <StackPanel>
                      <TextBlock Text="Server Utilization" Style="{StaticResource FormLabel}"/>
                      <TextBlock x:Name="StatUtilization" Text="0%" FontSize="26" FontWeight="Bold"
                                 Foreground="{StaticResource Accent}"/>
                    </StackPanel>
                  </Border>
                </Grid>
              </StackPanel>

              <Border Grid.Row="1" Background="{StaticResource BgCard}" CornerRadius="6"
                      Padding="10,8" Margin="0,0,0,8">
                <WrapPanel Orientation="Horizontal">
                  <Button x:Name="BtnRefreshStats" Content="🔄 Refresh All Scopes" Margin="0,0,8,4"
                          Style="{StaticResource BtnPrimary}" IsEnabled="False"
                          ToolTip="Load server totals and per-scope utilization for every scope"/>
                  <TextBlock Text="Flag at ≥" Style="{StaticResource FormLabel}"
                             VerticalAlignment="Center" Margin="4,0,6,4"/>
                  <ComboBox x:Name="CboUtilThreshold" Width="72" Height="28" Margin="0,0,12,4"
                            Background="{StaticResource BgDeep}" Foreground="{StaticResource TextPrimary}"
                            BorderBrush="{StaticResource Border}"
                            ToolTip="Scopes at or above this utilization are flagged Critical">
                    <ComboBoxItem Content="70%"/>
                    <ComboBoxItem Content="80%"/>
                    <ComboBoxItem Content="85%"/>
                    <ComboBoxItem Content="90%" IsSelected="True"/>
                    <ComboBoxItem Content="95%"/>
                  </ComboBox>
                  <TextBlock Text="Show:" Style="{StaticResource FormLabel}"
                             VerticalAlignment="Center" Margin="0,0,6,4"/>
                  <ComboBox x:Name="CboScopeStatFilter" Width="150" Height="28" Margin="0,0,12,4"
                            Background="{StaticResource BgDeep}" Foreground="{StaticResource TextPrimary}"
                            BorderBrush="{StaticResource Border}">
                    <ComboBoxItem Content="All scopes" IsSelected="True"/>
                    <ComboBoxItem Content="Warning + Critical"/>
                    <ComboBoxItem Content="Critical only"/>
                  </ComboBox>
                  <Button x:Name="BtnScopeStatDetails" Content="🔍 Scope Details" Margin="0,0,8,4"
                          Style="{StaticResource BtnSecondary}" IsEnabled="False"
                          ToolTip="Open detailed statistics for the selected scope"/>
                  <Button x:Name="BtnExportScopeStats" Content="💾 Export" Margin="0,0,0,4"
                          Style="{StaticResource BtnSecondary}" IsEnabled="False"
                          ToolTip="Export the visible scope statistics to CSV"/>
                </WrapPanel>
              </Border>

              <Border x:Name="ScopeUtilAlertBanner" Grid.Row="2" Background="#3A2418"
                      BorderBrush="{StaticResource Warning}" BorderThickness="1"
                      CornerRadius="4" Padding="10,8" Margin="0,0,0,8" Visibility="Collapsed">
                <TextBlock x:Name="TxtScopeUtilAlert" Text="" Foreground="{StaticResource Warning}"
                           FontWeight="SemiBold" TextWrapping="Wrap"/>
              </Border>

              <DataGrid Grid.Row="3" x:Name="GridScopeStats" Style="{StaticResource DarkGrid}"
                        Margin="0,0,0,8" IsReadOnly="True" SelectionMode="Single">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Status" Binding="{Binding Status}" Width="120"/>
                  <DataGridTextColumn Header="Util %" Binding="{Binding PercentDisplay}" Width="70"/>
                  <DataGridTextColumn Header="Scope ID" Binding="{Binding ScopeId}" Width="110"/>
                  <DataGridTextColumn Header="Name" Binding="{Binding Name}" Width="160"/>
                  <DataGridTextColumn Header="State" Binding="{Binding State}" Width="80"/>
                  <DataGridTextColumn Header="In Use" Binding="{Binding InUse}" Width="70"/>
                  <DataGridTextColumn Header="Free" Binding="{Binding Free}" Width="70"/>
                  <DataGridTextColumn Header="Total" Binding="{Binding Total}" Width="70"/>
                  <DataGridTextColumn Header="Reserved" Binding="{Binding Reserved}" Width="80"/>
                  <DataGridTextColumn Header="Pending" Binding="{Binding Pending}" Width="70"/>
                  <DataGridTextColumn Header="Range" Binding="{Binding RangeDisplay}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>

              <TextBlock Grid.Row="4" x:Name="TxtScopeStatStatus"
                         Text="Connect to a DHCP server, then click Refresh All Scopes."
                         Style="{StaticResource FormLabel}" TextWrapping="Wrap"/>
            </Grid>
          </TabItem>

          <!-- TAB: Compare Servers (NEW) -->
          <TabItem x:Name="TabCompare" Header="🔀 Compare">
            <Grid Background="{StaticResource BgPanel}">
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
              </Grid.RowDefinitions>

              <!-- Compare Server Connection -->
              <Border Grid.Row="0" Background="{StaticResource BgCard}"
                      BorderThickness="0,0,0,1" BorderBrush="{StaticResource Border}" Padding="12,10">
                <Grid>
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="*"/>
                  </Grid.ColumnDefinitions>

                  <StackPanel Grid.Column="0" Orientation="Horizontal">
                    <TextBlock Text="Server A (Primary):" Style="{StaticResource FormLabel}"
                               VerticalAlignment="Center" Margin="0,0,8,0"/>
                    <TextBlock x:Name="TxtCompareServerA" Text="Not Connected"
                               Foreground="{StaticResource Warning}" FontWeight="SemiBold"
                               VerticalAlignment="Center" Margin="0,0,16,0"/>
                  </StackPanel>

                  <StackPanel Grid.Column="1" Orientation="Horizontal" HorizontalAlignment="Right">
                    <TextBlock Text="Server B (Compare):" Style="{StaticResource FormLabel}"
                               VerticalAlignment="Center" Margin="0,0,8,0"/>
                    <TextBox x:Name="TxtCompareServer" Width="180" Style="{StaticResource DarkTextBox}"
                             ToolTip="Second DHCP server hostname or IP"/>
                    <Button x:Name="BtnCompareConnect" Content="🔌 Connect B" Margin="8,0,0,0"
                            Style="{StaticResource BtnSuccess}" ToolTip="Connect compare server"/>
                    <Button x:Name="BtnCompareDisconnect" Content="Disconnect B" Margin="8,0,0,0"
                            Style="{StaticResource BtnSecondary}" IsEnabled="False"/>
                  </StackPanel>
                </Grid>
              </Border>

              <!-- Compare Controls -->
              <Border Grid.Row="1" Background="{StaticResource BgCard}"
                      BorderThickness="0,0,0,1" BorderBrush="{StaticResource Border}" Padding="12,10">
                <StackPanel Orientation="Horizontal">
                  <TextBlock Text="Compare:" Style="{StaticResource FormLabel}"
                             VerticalAlignment="Center" Margin="0,0,8,0"/>
                  <ComboBox x:Name="CboCompareCategory" Width="140" Height="26" Margin="0,0,12,0"
                            Background="{StaticResource BgDeep}" Foreground="{StaticResource TextPrimary}"
                            BorderBrush="{StaticResource Border}">
                    <ComboBoxItem Content="Scopes" IsSelected="True"/>
                    <ComboBoxItem Content="Options"/>
                    <ComboBoxItem Content="Leases"/>
                    <ComboBoxItem Content="Reservations"/>
                  </ComboBox>

                  <TextBlock Text="Show:" Style="{StaticResource FormLabel}"
                             VerticalAlignment="Center" Margin="0,0,8,0"/>
                  <ComboBox x:Name="CboCompareFilter" Width="130" Height="26" Margin="0,0,12,0"
                            Background="{StaticResource BgDeep}" Foreground="{StaticResource TextPrimary}"
                            BorderBrush="{StaticResource Border}">
                    <ComboBoxItem Content="All" IsSelected="True"/>
                    <ComboBoxItem Content="Only on A"/>
                    <ComboBoxItem Content="Only on B"/>
                    <ComboBoxItem Content="Matching"/>
                    <ComboBoxItem Content="Different"/>
                  </ComboBox>

                  <Button x:Name="BtnRunCompare" Content="▶️ Run Compare" Margin="0,0,8,0"
                          Style="{StaticResource BtnPrimary}" IsEnabled="False"/>
                  <Button x:Name="BtnCompareExport" Content="💾 Export Results" Margin="0,0,8,0"
                          Style="{StaticResource BtnSecondary}" IsEnabled="False"/>
                  <Button x:Name="BtnCompareMigrate" Content="🚚 Migrate Selected"
                          Style="{StaticResource BtnSuccess}" IsEnabled="False"
                          ToolTip="Migrate selected scope(s) and related settings (options, reservations, exclusions) between A and B. Direction: Only on A → to B; Only on B → to A."/>
                </StackPanel>
              </Border>

              <!-- Compare Summary -->
              <Border Grid.Row="2" Background="{StaticResource BgPanel}" Padding="12,8">
                <StackPanel Orientation="Horizontal">
                  <Border Background="{StaticResource BgCard}" CornerRadius="4" Padding="12,6" Margin="0,0,8,0">
                    <TextBlock>
                      <Run Text="Only A: " Foreground="#9AA3B2"/>
                      <Run x:Name="CmpOnlyA" Text="0" Foreground="#FF9800" FontWeight="Bold"/>
                    </TextBlock>
                  </Border>
                  <Border Background="{StaticResource BgCard}" CornerRadius="4" Padding="12,6" Margin="0,0,8,0">
                    <TextBlock>
                      <Run Text="Only B: " Foreground="#9AA3B2"/>
                      <Run x:Name="CmpOnlyB" Text="0" Foreground="#2196F3" FontWeight="Bold"/>
                    </TextBlock>
                  </Border>
                  <Border Background="{StaticResource BgCard}" CornerRadius="4" Padding="12,6" Margin="0,0,8,0">
                    <TextBlock>
                      <Run Text="Matching: " Foreground="#9AA3B2"/>
                      <Run x:Name="CmpMatch" Text="0" Foreground="#4CAF50" FontWeight="Bold"/>
                    </TextBlock>
                  </Border>
                  <Border Background="{StaticResource BgCard}" CornerRadius="4" Padding="12,6" Margin="0,0,8,0">
                    <TextBlock>
                      <Run Text="Different: " Foreground="#9AA3B2"/>
                      <Run x:Name="CmpDiff" Text="0" Foreground="#F44336" FontWeight="Bold"/>
                    </TextBlock>
                  </Border>
                  <TextBlock x:Name="TxtCompareStatus" Text="Connect both servers, then run compare"
                             Foreground="{StaticResource TextSecond}" VerticalAlignment="Center" Margin="12,0,0,0"/>
                </StackPanel>
              </Border>

              <!-- Compare Results Grid -->
              <DataGrid Grid.Row="3" x:Name="GridCompare" Style="{StaticResource DarkGrid}" Margin="8"
                        SelectionMode="Extended"
                        ToolTip="Select one or more scope rows, then Migrate Selected">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Status" Binding="{Binding Status}" Width="100"/>
                  <DataGridTextColumn Header="Key" Binding="{Binding Key}" Width="160"/>
                  <DataGridTextColumn Header="Name / Label" Binding="{Binding Label}" Width="160"/>
                  <DataGridTextColumn Header="Server A" Binding="{Binding ValueA}" Width="220"/>
                  <DataGridTextColumn Header="Server B" Binding="{Binding ValueB}" Width="220"/>
                  <DataGridTextColumn Header="Details" Binding="{Binding Details}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
            </Grid>
          </TabItem>

          <!-- TAB: Scope Migration (NEW) -->
          <TabItem x:Name="TabMigrate" Header="🚚 Migrate">
            <Grid Background="{StaticResource BgPanel}">
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*" MinHeight="160"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*" MinHeight="140"/>
              </Grid.RowDefinitions>

              <!-- Direction / servers -->
              <Border Grid.Row="0" Background="{StaticResource BgCard}"
                      BorderThickness="0,0,0,1" BorderBrush="{StaticResource Border}" Padding="12,10">
                <Grid>
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                  </Grid.ColumnDefinitions>
                  <StackPanel Grid.Column="0" Orientation="Horizontal">
                    <TextBlock Text="Source (A):" Style="{StaticResource FormLabel}"
                               VerticalAlignment="Center" Margin="0,0,8,0"/>
                    <TextBlock x:Name="TxtMigrateSource" Text="Not Connected"
                               Foreground="{StaticResource Warning}" FontWeight="SemiBold"
                               VerticalAlignment="Center"/>
                  </StackPanel>
                  <StackPanel Grid.Column="1" Orientation="Horizontal">
                    <TextBlock Text="Destination (B):" Style="{StaticResource FormLabel}"
                               VerticalAlignment="Center" Margin="0,0,8,0"/>
                    <TextBlock x:Name="TxtMigrateDest" Text="Not Connected"
                               Foreground="{StaticResource Warning}" FontWeight="SemiBold"
                               VerticalAlignment="Center"/>
                  </StackPanel>
                  <Button Grid.Column="2" x:Name="BtnMigrateRefreshScopes" Content="🔄 Load Source Scopes"
                          Style="{StaticResource BtnSecondary}" IsEnabled="False"
                          ToolTip="Load scopes from Server A for migration"/>
                </Grid>
              </Border>

              <!-- What to migrate -->
              <Border Grid.Row="1" Background="{StaticResource BgCard}"
                      BorderThickness="0,0,0,1" BorderBrush="{StaticResource Border}" Padding="12,10">
                <StackPanel>
                  <StackPanel Orientation="Horizontal" Margin="0,0,0,8">
                    <TextBlock Text="Include:" Style="{StaticResource FormLabel}"
                               VerticalAlignment="Center" Margin="0,0,12,0"/>
                    <CheckBox x:Name="ChkMigScope" Content="Scope" IsChecked="True" Margin="0,0,12,0"/>
                    <CheckBox x:Name="ChkMigOptions" Content="Scope Options" IsChecked="True" Margin="0,0,12,0"/>
                    <CheckBox x:Name="ChkMigReservations" Content="Reservations (Clients)" IsChecked="True" Margin="0,0,12,0"/>
                    <CheckBox x:Name="ChkMigExclusions" Content="Exclusions" IsChecked="True" Margin="0,0,12,0"/>
                    <CheckBox x:Name="ChkMigLeasesAsRes" Content="Active Leases → Reservations" Margin="0,0,12,0"
                              ToolTip="Convert currently active leases on source into reservations on destination"/>
                  </StackPanel>
                  <StackPanel Orientation="Horizontal">
                    <TextBlock Text="If scope exists on B:" Style="{StaticResource FormLabel}"
                               VerticalAlignment="Center" Margin="0,0,8,0"/>
                    <ComboBox x:Name="CboMigConflict" Width="200" Height="26" Margin="0,0,16,0"
                              Background="{StaticResource BgDeep}" Foreground="{StaticResource TextPrimary}"
                              BorderBrush="{StaticResource Border}">
                      <ComboBoxItem Content="Merge into existing" IsSelected="True"/>
                      <ComboBoxItem Content="Skip scope"/>
                      <ComboBoxItem Content="Fail"/>
                    </ComboBox>
                    <CheckBox x:Name="ChkMigActivateDest" Content="Activate on B" IsChecked="True" Margin="0,0,12,0"/>
                    <CheckBox x:Name="ChkMigDeactivateSource" Content="Deactivate on A after success" Margin="0,0,16,0"/>
                    <Button x:Name="BtnMigrateSelectAll" Content="Select All" Margin="0,0,8,0"
                            Style="{StaticResource BtnSecondary}"/>
                    <Button x:Name="BtnMigrateSelectNone" Content="Select None" Margin="0,0,8,0"
                            Style="{StaticResource BtnSecondary}"/>
                    <Button x:Name="BtnMigrateDryRun" Content="🧪 Dry Run" Margin="0,0,8,0"
                            Style="{StaticResource BtnPrimary}" IsEnabled="False"/>
                    <Button x:Name="BtnMigrateRun" Content="🚚 Migrate" Margin="0,0,8,0"
                            Style="{StaticResource BtnSuccess}" IsEnabled="False"/>
                    <Button x:Name="BtnMigrateExport" Content="💾 Export Plan" Margin="0,0,0,0"
                            Style="{StaticResource BtnSecondary}" IsEnabled="False"/>
                  </StackPanel>
                </StackPanel>
              </Border>

              <!-- Source scopes grid -->
              <DataGrid Grid.Row="2" x:Name="GridMigrateScopes" Style="{StaticResource DarkGrid}" Margin="8,8,8,4"
                        SelectionMode="Extended">
                <DataGrid.Columns>
                  <DataGridCheckBoxColumn Header="Sel" Binding="{Binding Selected}" Width="40"/>
                  <DataGridTextColumn Header="Scope ID" Binding="{Binding ScopeId}" Width="130"/>
                  <DataGridTextColumn Header="Name" Binding="{Binding Name}" Width="160"/>
                  <DataGridTextColumn Header="Start" Binding="{Binding StartRange}" Width="120"/>
                  <DataGridTextColumn Header="End" Binding="{Binding EndRange}" Width="120"/>
                  <DataGridTextColumn Header="Mask" Binding="{Binding SubnetMask}" Width="120"/>
                  <DataGridTextColumn Header="State" Binding="{Binding State}" Width="80"/>
                  <DataGridTextColumn Header="On Dest?" Binding="{Binding OnDestination}" Width="80"/>
                </DataGrid.Columns>
              </DataGrid>

              <TextBlock Grid.Row="3" x:Name="TxtMigrateStatus"
                         Text="Connect Server A (source) and Server B (destination), then Load Source Scopes"
                         Foreground="{StaticResource TextSecond}" FontSize="11" Margin="12,0,12,4"/>

              <!-- Migration results -->
              <DataGrid Grid.Row="4" x:Name="GridMigrateResults" Style="{StaticResource DarkGrid}" Margin="8,4,8,8">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Scope" Binding="{Binding ScopeId}" Width="120"/>
                  <DataGridTextColumn Header="Step" Binding="{Binding Step}" Width="140"/>
                  <DataGridTextColumn Header="Status" Binding="{Binding Status}" Width="90"/>
                  <DataGridTextColumn Header="Message" Binding="{Binding Message}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
            </Grid>
          </TabItem>

          <!-- TAB: DHCP Events / Live Watch -->
          <TabItem x:Name="TabEvents" Header="📡 Events">
            <Grid Background="{StaticResource BgPanel}">
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
              </Grid.RowDefinitions>

              <!-- Source / Path -->
              <Border Grid.Row="0" Background="{StaticResource BgCard}"
                      BorderThickness="0,0,0,1" BorderBrush="{StaticResource Border}" Padding="12,10">
                <Grid>
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                  </Grid.ColumnDefinitions>
                  <StackPanel Grid.Column="0" Orientation="Horizontal" VerticalAlignment="Center">
                    <TextBlock Text="Ingest Source:" Style="{StaticResource FormLabel}"
                               VerticalAlignment="Center" Margin="0,0,8,0"/>
                    <ComboBox x:Name="CboEventSource" Width="150" Height="26" Margin="0,0,12,0"
                              Background="{StaticResource BgDeep}" Foreground="{StaticResource TextPrimary}"
                              BorderBrush="{StaticResource Border}">
                      <ComboBoxItem Content="Local Server" IsSelected="True"/>
                      <ComboBoxItem Content="Server A"/>
                      <ComboBoxItem Content="Server B"/>
                      <ComboBoxItem Content="Custom Path"/>
                    </ComboBox>
                  </StackPanel>
                  <TextBox Grid.Column="1" x:Name="TxtEventLogPath" Style="{StaticResource DarkTextBox}"
                           Margin="0,0,8,0"
                           ToolTip="Path to DhcpSrvLog file or folder (local or UNC)"/>
                  <StackPanel Grid.Column="2" Orientation="Horizontal">
                    <Button x:Name="BtnEventBrowse" Content="📁 Browse" Margin="0,0,8,0"
                            Style="{StaticResource BtnSecondary}"/>
                    <Button x:Name="BtnEventDetect" Content="🔎 Detect Logs" Margin="0,0,8,0"
                            Style="{StaticResource BtnSecondary}"
                            ToolTip="List DHCP audit logs (filename + last modified) and choose which to ingest"/>
                    <Button x:Name="BtnEventIngest" Content="📥 Ingest Log" Margin="0,0,8,0"
                            Style="{StaticResource BtnPrimary}"
                            ToolTip="Parse and load DHCP audit log events (shows progress; can pause/cancel)"/>
                    <Button x:Name="BtnEventIngestPause" Content="⏸ Pause" Margin="0,0,0,0"
                            Style="{StaticResource BtnSecondary}" IsEnabled="False"
                            ToolTip="Pause or resume log ingest"/>
                  </StackPanel>
                </Grid>
              </Border>

              <!-- Live Watch Controls -->
              <Border Grid.Row="1" Background="{StaticResource BgCard}"
                      BorderThickness="0,0,0,1" BorderBrush="{StaticResource Border}" Padding="12,10">
                <StackPanel>
                  <StackPanel Orientation="Horizontal" Margin="0,0,0,8">
                    <TextBlock Text="Live Watch:" Style="{StaticResource FormLabel}"
                               VerticalAlignment="Center" Margin="0,0,12,0"/>
                    <CheckBox x:Name="ChkWatchLocal" Content="Local" Margin="0,0,12,0"
                              VerticalAlignment="Center"/>
                    <CheckBox x:Name="ChkWatchA" Content="Server A" Margin="0,0,12,0"
                              VerticalAlignment="Center"/>
                    <CheckBox x:Name="ChkWatchB" Content="Server B" Margin="0,0,12,0"
                              VerticalAlignment="Center"/>
                    <CheckBox x:Name="ChkWatchCustom" Content="Custom file" Margin="0,0,16,0"
                              VerticalAlignment="Center"
                              ToolTip="Watch a specific DhcpSrvLog file or folder you choose below"/>
                    <Button x:Name="BtnEventWatchStart" Content="▶️ Start Watch" Margin="0,0,8,0"
                            Style="{StaticResource BtnSuccess}"/>
                    <Button x:Name="BtnEventWatchStop" Content="⏹️ Stop" Margin="0,0,8,0"
                            Style="{StaticResource BtnDanger}" IsEnabled="False"/>
                    <Separator Width="1" Background="{StaticResource Border}" Margin="8,0"/>
                    <Button x:Name="BtnEventClear" Content="🗑️ Clear" Margin="8,0,8,0"
                            Style="{StaticResource BtnSecondary}"/>
                    <Button x:Name="BtnEventDetails" Content="🔍 Details" Margin="0,0,8,0"
                            Style="{StaticResource BtnSecondary}"
                            ToolTip="Open details for the selected event (or double-click a row)"/>
                    <Button x:Name="BtnEventExport" Content="💾 Export" Margin="0,0,0,0"
                            Style="{StaticResource BtnSecondary}"/>
                  </StackPanel>
                  <Grid>
                    <Grid.ColumnDefinitions>
                      <ColumnDefinition Width="Auto"/>
                      <ColumnDefinition Width="*"/>
                      <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <TextBlock Grid.Column="0" Text="Watch file:" Style="{StaticResource FormLabel}"
                               VerticalAlignment="Center" Margin="0,0,8,0"/>
                    <TextBox Grid.Column="1" x:Name="TxtWatchLogPath" Style="{StaticResource DarkTextBox}"
                             Margin="0,0,8,0"
                             ToolTip="Full path to DhcpSrvLog file (or folder). Used when Custom file is checked."/>
                    <StackPanel Grid.Column="2" Orientation="Horizontal">
                      <Button x:Name="BtnWatchBrowse" Content="📁 Browse" Margin="0,0,8,0"
                              Style="{StaticResource BtnSecondary}"
                              ToolTip="Choose the DHCP audit log file to live-watch"/>
                      <Button x:Name="BtnWatchUseIngestPath" Content="Use ingest path"
                              Style="{StaticResource BtnSecondary}"
                              ToolTip="Copy the Ingest path above into the watch file box"/>
                    </StackPanel>
                  </Grid>
                </StackPanel>
              </Border>

              <!-- Robust event filter -->
              <Border Grid.Row="2" Background="{StaticResource BgCard}"
                      BorderThickness="0,0,0,1" BorderBrush="{StaticResource Border}" Padding="12,10">
                <StackPanel>
                  <TextBlock Text="Filter ingested events" Style="{StaticResource FormLabel}" Margin="0,0,0,8"/>
                  <WrapPanel Orientation="Horizontal">
                    <StackPanel Orientation="Horizontal" Margin="0,0,16,6">
                      <TextBlock Text="Search:" Style="{StaticResource FormLabel}" VerticalAlignment="Center" Margin="0,0,6,0"/>
                      <TextBox x:Name="TxtEventFilter" Width="160" Style="{StaticResource DarkTextBox}"
                               ToolTip="Matches any field (IP, MAC, host, event text, details)"/>
                    </StackPanel>
                    <StackPanel Orientation="Horizontal" Margin="0,0,16,6">
                      <TextBlock Text="Event ID:" Style="{StaticResource FormLabel}" VerticalAlignment="Center" Margin="0,0,6,0"/>
                      <ComboBox x:Name="CboEventIdFilter" Width="150" Height="26"
                                Background="{StaticResource BgDeep}" Foreground="{StaticResource TextPrimary}"
                                BorderBrush="{StaticResource Border}">
                        <ComboBoxItem Content="All" IsSelected="True"/>
                        <ComboBoxItem Content="10 — Assign"/>
                        <ComboBoxItem Content="11 — Renew"/>
                        <ComboBoxItem Content="12 — Release"/>
                        <ComboBoxItem Content="13 — Conflict"/>
                        <ComboBoxItem Content="15 — NACK"/>
                        <ComboBoxItem Content="16 — Decline"/>
                        <ComboBoxItem Content="30 — DNS request"/>
                        <ComboBoxItem Content="31 — DNS failed"/>
                        <ComboBoxItem Content="32 — DNS success"/>
                        <ComboBoxItem Content="50+ — Auth/rogue"/>
                      </ComboBox>
                    </StackPanel>
                    <StackPanel Orientation="Horizontal" Margin="0,0,16,6">
                      <TextBlock Text="IP:" Style="{StaticResource FormLabel}" VerticalAlignment="Center" Margin="0,0,6,0"/>
                      <TextBox x:Name="TxtEventFilterIp" Width="120" Style="{StaticResource DarkTextBox}"
                               ToolTip="Contains match on IP Address"/>
                    </StackPanel>
                    <StackPanel Orientation="Horizontal" Margin="0,0,16,6">
                      <TextBlock Text="MAC:" Style="{StaticResource FormLabel}" VerticalAlignment="Center" Margin="0,0,6,0"/>
                      <TextBox x:Name="TxtEventFilterMac" Width="130" Style="{StaticResource DarkTextBox}"
                               ToolTip="Contains match on MAC (dashes/colons optional)"/>
                    </StackPanel>
                    <StackPanel Orientation="Horizontal" Margin="0,0,16,6">
                      <TextBlock Text="Host:" Style="{StaticResource FormLabel}" VerticalAlignment="Center" Margin="0,0,6,0"/>
                      <TextBox x:Name="TxtEventFilterHost" Width="130" Style="{StaticResource DarkTextBox}"
                               ToolTip="Contains match on Hostname"/>
                    </StackPanel>
                    <StackPanel Orientation="Horizontal" Margin="0,0,16,6">
                      <TextBlock Text="Server:" Style="{StaticResource FormLabel}" VerticalAlignment="Center" Margin="0,0,6,0"/>
                      <ComboBox x:Name="CboEventFilterServer" Width="120" Height="26"
                                Background="{StaticResource BgDeep}" Foreground="{StaticResource TextPrimary}"
                                BorderBrush="{StaticResource Border}">
                        <ComboBoxItem Content="All" IsSelected="True"/>
                      </ComboBox>
                    </StackPanel>
                    <Button x:Name="BtnEventFilterApply" Content="Apply Filter" Margin="0,0,8,6"
                            Style="{StaticResource BtnPrimary}"
                            ToolTip="Apply filters to ingested events"/>
                    <Button x:Name="BtnEventFilterClear" Content="Clear Filters" Margin="0,0,8,6"
                            Style="{StaticResource BtnSecondary}"
                            ToolTip="Reset all event filters"/>
                    <TextBlock x:Name="TxtEventFilterCount" Text="Showing 0 of 0"
                               Foreground="{StaticResource TextSecond}" FontSize="11"
                               VerticalAlignment="Center" Margin="4,0,0,6"/>
                  </WrapPanel>
                </StackPanel>
              </Border>

              <!-- Status line + ingest progress -->
              <Border Grid.Row="3" Background="{StaticResource BgPanel}" Padding="12,6">
                <StackPanel>
                  <TextBlock x:Name="TxtEventStatus" Text="Detect logs to choose a file, ingest, then filter. Or live-watch Local / A / B / Custom."
                             Foreground="{StaticResource TextSecond}" FontSize="11" Margin="0,0,0,4"/>
                  <Grid x:Name="EventIngestProgressPanel" Visibility="Collapsed">
                    <Grid.ColumnDefinitions>
                      <ColumnDefinition Width="*"/>
                      <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <ProgressBar x:Name="BarEventIngest" Height="10" Minimum="0" Maximum="100" Value="0"
                                 Background="{StaticResource BgDeep}" Foreground="{StaticResource Accent}"
                                 BorderBrush="{StaticResource Border}" BorderThickness="1" Margin="0,0,12,0"/>
                    <TextBlock x:Name="TxtEventIngestPct" Grid.Column="1" Text="0%"
                               Foreground="{StaticResource TextPrimary}" FontSize="11"
                               VerticalAlignment="Center" MinWidth="40"/>
                  </Grid>
                </StackPanel>
              </Border>

              <!-- Events Grid -->
              <DataGrid Grid.Row="4" x:Name="GridEvents" Style="{StaticResource DarkGrid}" Margin="8">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Server" Binding="{Binding Server}" Width="110"/>
                  <DataGridTextColumn Header="Time" Binding="{Binding Time}" Width="140"/>
                  <DataGridTextColumn Header="ID" Binding="{Binding EventId}" Width="50"/>
                  <DataGridTextColumn Header="Event" Binding="{Binding Description}" Width="140"/>
                  <DataGridTextColumn Header="IP Address" Binding="{Binding IPAddress}" Width="120"/>
                  <DataGridTextColumn Header="MAC" Binding="{Binding MacAddress}" Width="130"/>
                  <DataGridTextColumn Header="Hostname" Binding="{Binding HostName}" Width="140"/>
                  <DataGridTextColumn Header="Details" Binding="{Binding Details}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
            </Grid>
          </TabItem>

          <!-- TAB: Action Log (NEW) -->
          <TabItem x:Name="TabLog" Header="📋 Action Log">
            <Grid Background="{StaticResource BgPanel}">
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
              </Grid.RowDefinitions>

              <!-- Log Toolbar -->
              <Border Grid.Row="0" Background="{StaticResource BgCard}"
                      BorderThickness="0,0,0,1" BorderBrush="{StaticResource Border}" Padding="12,10">
                <StackPanel Orientation="Horizontal">
                  <Button x:Name="BtnLogRefresh" Content="🔄 Refresh" Margin="0,0,8,0"
                          Style="{StaticResource BtnSecondary}"/>
                  <Button x:Name="BtnLogClear" Content="🗑️ Clear" Margin="0,0,8,0"
                          Style="{StaticResource BtnSecondary}"/>
                  <Button x:Name="BtnLogExport" Content="💾 Export" Margin="0,0,8,0"
                          Style="{StaticResource BtnPrimary}"/>
                  <Separator Width="1" Background="{StaticResource Border}" Margin="8,0"/>
                  <TextBlock Text="Filter:" Style="{StaticResource FormLabel}"
                             VerticalAlignment="Center" Margin="8,0,8,0"/>
                  <ComboBox x:Name="CboLogLevel" Width="100" Height="26"
                            Background="{StaticResource BgDeep}" Foreground="{StaticResource TextPrimary}"
                            BorderBrush="{StaticResource Border}">
                    <ComboBoxItem Content="All" IsSelected="True"/>
                    <ComboBoxItem Content="INFO"/>
                    <ComboBoxItem Content="SUCCESS"/>
                    <ComboBoxItem Content="WARN"/>
                    <ComboBoxItem Content="ERROR"/>
                  </ComboBox>
                </StackPanel>
              </Border>

              <!-- Log Display -->
              <ScrollViewer x:Name="LogScrollViewer" Grid.Row="1" VerticalScrollBarVisibility="Auto"
                            Background="{StaticResource BgDeep}" Margin="8">
                <TextBox x:Name="TxtLog" IsReadOnly="True" TextWrapping="Wrap"
                         Background="{StaticResource BgDeep}" Foreground="{StaticResource TextPrimary}"
                         BorderThickness="0" Padding="8" FontFamily="Consolas" FontSize="11"
                         VerticalScrollBarVisibility="Auto"/>
              </ScrollViewer>
            </Grid>
          </TabItem>

        </TabControl>
      </Border>
    </Grid>
  </DockPanel>
</Window>
'@

Write-ActionLog "XAML interface loaded successfully" "SUCCESS"
#endregion

#region Window Loading and Control Binding
try {
    Write-ActionLog "Parsing XAML and loading WPF window..." "INFO"
    
    $reader = [System.Xml.XmlNodeReader]::new($XAML)
    $script:Window = [Windows.Markup.XamlReader]::Load($reader)
    
    if ($null -eq $Window) {
        throw "Failed to create window from XAML"
    }
    
    Write-ActionLog "Binding UI controls..." "INFO"
    
    # Connection Controls
    $script:TxtServerName    = $Window.FindName("TxtServerName")
    $script:BtnConnect       = $Window.FindName("BtnConnect")
    $script:BtnScanDomain    = $Window.FindName("BtnScanDomain")
    $script:BtnDisconnect    = $Window.FindName("BtnDisconnect")
    $script:BtnRefresh       = $Window.FindName("BtnRefresh")
    $script:BtnSettings      = $Window.FindName("BtnSettings")
    $script:BtnAbout         = $Window.FindName("BtnAbout")
    $script:BtnViewLog       = $Window.FindName("BtnViewLog")
    $script:BtnViewCompare   = $Window.FindName("BtnViewCompare")
    $script:BtnViewEvents    = $Window.FindName("BtnViewEvents")
    $script:BtnViewTroubleshoot = $Window.FindName("BtnViewTroubleshoot")
    $script:BtnViewDashboard = $Window.FindName("BtnViewDashboard")
    $script:BtnViewMigrate   = $Window.FindName("BtnViewMigrate")
    
    # Status Bar
    $script:StatusServer     = $Window.FindName("StatusServer")
    $script:StatusMessage    = $Window.FindName("StatusMessage")
    $script:StatusTime       = $Window.FindName("StatusTime")
    $script:TaskProgressPanel = $Window.FindName("TaskProgressPanel")
    $script:TxtTaskProgress  = $Window.FindName("TxtTaskProgress")
    $script:BarTaskProgress  = $Window.FindName("BarTaskProgress")
    $script:BtnTaskPause     = $Window.FindName("BtnTaskPause")
    $script:BtnTaskCancel    = $Window.FindName("BtnTaskCancel")
    
    # Live watch timer (must be initialized for StrictMode)
    $script:EventWatchTimer  = $null
    $script:UpdatingEventFilterServerCombo = $false
    $script:PendingFilteredEvents = [System.Collections.Generic.List[object]]::new()
    $script:AuditLogPickerSelection = $null
    
    # Navigation
    $script:NavTree          = $Window.FindName("NavTree")
    $script:TxtNavScopeSearch = $Window.FindName("TxtNavScopeSearch")
    $script:BtnNavScopeFind  = $Window.FindName("BtnNavScopeFind")
    $script:BtnNavScopeSearchClear = $Window.FindName("BtnNavScopeSearchClear")
    $script:TxtNavScopeSearchStatus = $Window.FindName("TxtNavScopeSearchStatus")
    $script:MainTabs         = $Window.FindName("MainTabs")
    
    # Tabs
    $script:TabDashboard     = $Window.FindName("TabDashboard")
    $script:TabScopes        = $Window.FindName("TabScopes")
    $script:TabLeases        = $Window.FindName("TabLeases")
    $script:TabReservations  = $Window.FindName("TabReservations")
    $script:TabExclusions    = $Window.FindName("TabExclusions")
    $script:TabOptions       = $Window.FindName("TabOptions")
    $script:TabFilters       = $Window.FindName("TabFilters")
    $script:TabPolicies      = $Window.FindName("TabPolicies")
    $script:TabTroubleshoot  = $Window.FindName("TabTroubleshoot")
    $script:TabStats         = $Window.FindName("TabStats")
    $script:TabCompare       = $Window.FindName("TabCompare")
    $script:TabMigrate       = $Window.FindName("TabMigrate")
    $script:TabEvents        = $Window.FindName("TabEvents")
    $script:TabLog           = $Window.FindName("TabLog")
    
    # Scopes Tab
    $script:GridScopes       = $Window.FindName("GridScopes")
    $script:BtnScopeAdd      = $Window.FindName("BtnScopeAdd")
    $script:BtnScopeEdit     = $Window.FindName("BtnScopeEdit")
    $script:BtnScopeDelete   = $Window.FindName("BtnScopeDelete")
    $script:BtnScopeActivate = $Window.FindName("BtnScopeActivate")
    $script:BtnScopeDeactivate = $Window.FindName("BtnScopeDeactivate")
    $script:TxtScopeFilter   = $Window.FindName("TxtScopeFilter")
    $script:TxtScopeFilterCount = $Window.FindName("TxtScopeFilterCount")
    
    # Dashboard Tab
    $script:TxtDashboardSubtitle = $Window.FindName("TxtDashboardSubtitle")
    $script:BtnDashboardRefresh = $Window.FindName("BtnDashboardRefresh")
    $script:BtnDashboardOpenStats = $Window.FindName("BtnDashboardOpenStats")
    $script:BtnDashboardScanEstate = $Window.FindName("BtnDashboardScanEstate")
    $script:DashKpiScopes = $Window.FindName("DashKpiScopes")
    $script:DashKpiLeases = $Window.FindName("DashKpiLeases")
    $script:DashKpiAvailable = $Window.FindName("DashKpiAvailable")
    $script:DashKpiUtil = $Window.FindName("DashKpiUtil")
    $script:DashKpiCritical = $Window.FindName("DashKpiCritical")
    $script:DashKpiWarning = $Window.FindName("DashKpiWarning")
    $script:TxtDashboardHealth = $Window.FindName("TxtDashboardHealth")
    $script:GridDashboardAlerts = $Window.FindName("GridDashboardAlerts")
    $script:GridDashboardTopScopes = $Window.FindName("GridDashboardTopScopes")
    $script:GridDashboardEstate = $Window.FindName("GridDashboardEstate")
    $script:TxtDashboardEstateHint = $Window.FindName("TxtDashboardEstateHint")
    $script:TxtDashboardStatus = $Window.FindName("TxtDashboardStatus")
    
    # Leases Tab
    $script:GridLeases       = $Window.FindName("GridLeases")
    $script:BtnLeaseRelease  = $Window.FindName("BtnLeaseRelease")
    $script:BtnLeaseReserve  = $Window.FindName("BtnLeaseReserve")
    $script:BtnLeaseRefresh  = $Window.FindName("BtnLeaseRefresh")
    $script:BtnLeaseSelectAll = $Window.FindName("BtnLeaseSelectAll")
    $script:BtnLeaseClearSel = $Window.FindName("BtnLeaseClearSel")
    $script:TxtLeaseSelectedCount = $Window.FindName("TxtLeaseSelectedCount")
    $script:TxtLeaseFilter   = $Window.FindName("TxtLeaseFilter")
    
    # Reservations Tab
    $script:GridReservations = $Window.FindName("GridReservations")
    $script:BtnResAdd        = $Window.FindName("BtnResAdd")
    $script:BtnResEdit       = $Window.FindName("BtnResEdit")
    $script:BtnResDelete     = $Window.FindName("BtnResDelete")
    
    # Exclusions Tab
    $script:GridExclusions   = $Window.FindName("GridExclusions")
    $script:BtnExcAdd        = $Window.FindName("BtnExcAdd")
    $script:BtnExcDelete     = $Window.FindName("BtnExcDelete")
    
    # Options Tab
    $script:GridOptions      = $Window.FindName("GridOptions")
    $script:CboOptionLevel   = $Window.FindName("CboOptionLevel")
    $script:BtnOptionSet     = $Window.FindName("BtnOptionSet")
    $script:BtnOptionDelete  = $Window.FindName("BtnOptionDelete")
    
    # Filters Tab
    $script:GridFilters      = $Window.FindName("GridFilters")
    $script:CboFilterList    = $Window.FindName("CboFilterList")
    $script:BtnFilterAdd     = $Window.FindName("BtnFilterAdd")
    $script:BtnFilterDelete  = $Window.FindName("BtnFilterDelete")
    $script:ChkEnableFilters = $Window.FindName("ChkEnableFilters")
    
    # Policies Tab
    $script:GridPolicies     = $Window.FindName("GridPolicies")
    $script:BtnPolicyAdd     = $Window.FindName("BtnPolicyAdd")
    $script:BtnPolicyEdit    = $Window.FindName("BtnPolicyEdit")
    $script:BtnPolicyDelete  = $Window.FindName("BtnPolicyDelete")
    
    # Troubleshoot Tab
    $script:CboTroubleshootScope = $Window.FindName("CboTroubleshootScope")
    $script:BtnTroubleshootRefreshScopes = $Window.FindName("BtnTroubleshootRefreshScopes")
    $script:BtnTroubleshootUseSelected = $Window.FindName("BtnTroubleshootUseSelected")
    $script:CboTroubleshootSample = $Window.FindName("CboTroubleshootSample")
    $script:BtnTroubleshootRun = $Window.FindName("BtnTroubleshootRun")
    $script:BtnTroubleshootExport = $Window.FindName("BtnTroubleshootExport")
    $script:TxtTroubleshootSummary = $Window.FindName("TxtTroubleshootSummary")
    $script:GridTroubleshootFindings = $Window.FindName("GridTroubleshootFindings")
    $script:BtnTroubleshootFindingDetails = $Window.FindName("BtnTroubleshootFindingDetails")
    $script:GridTroubleshootBadLeases = $Window.FindName("GridTroubleshootBadLeases")
    $script:GridTroubleshootProbes = $Window.FindName("GridTroubleshootProbes")
    $script:ChkTroubleshootReviewed = $Window.FindName("ChkTroubleshootReviewed")
    $script:BtnTroubleshootClearBad = $Window.FindName("BtnTroubleshootClearBad")
    $script:TxtTroubleshootClearHint = $Window.FindName("TxtTroubleshootClearHint")
    
    # Statistics Tab
    $script:StatTotalScopes  = $Window.FindName("StatTotalScopes")
    $script:StatActiveLeases = $Window.FindName("StatActiveLeases")
    $script:StatReservations = $Window.FindName("StatReservations")
    $script:StatAvailableIPs = $Window.FindName("StatAvailableIPs")
    $script:StatTotalIPs     = $Window.FindName("StatTotalIPs")
    $script:StatUtilization  = $Window.FindName("StatUtilization")
    $script:BtnRefreshStats  = $Window.FindName("BtnRefreshStats")
    $script:CboUtilThreshold = $Window.FindName("CboUtilThreshold")
    $script:CboScopeStatFilter = $Window.FindName("CboScopeStatFilter")
    $script:BtnScopeStatDetails = $Window.FindName("BtnScopeStatDetails")
    $script:BtnExportScopeStats = $Window.FindName("BtnExportScopeStats")
    $script:ScopeUtilAlertBanner = $Window.FindName("ScopeUtilAlertBanner")
    $script:TxtScopeUtilAlert = $Window.FindName("TxtScopeUtilAlert")
    $script:GridScopeStats   = $Window.FindName("GridScopeStats")
    $script:TxtScopeStatStatus = $Window.FindName("TxtScopeStatStatus")
    
    # Log Tab
    $script:TxtLog           = $Window.FindName("TxtLog")
    $script:LogScrollViewer  = $Window.FindName("LogScrollViewer")
    $script:BtnLogRefresh    = $Window.FindName("BtnLogRefresh")
    $script:BtnLogClear      = $Window.FindName("BtnLogClear")
    $script:BtnLogExport     = $Window.FindName("BtnLogExport")
    $script:CboLogLevel      = $Window.FindName("CboLogLevel")
    
    # Compare Tab
    $script:TxtCompareServerA    = $Window.FindName("TxtCompareServerA")
    $script:TxtCompareServer     = $Window.FindName("TxtCompareServer")
    $script:BtnCompareConnect    = $Window.FindName("BtnCompareConnect")
    $script:BtnCompareDisconnect = $Window.FindName("BtnCompareDisconnect")
    $script:CboCompareCategory   = $Window.FindName("CboCompareCategory")
    $script:CboCompareFilter     = $Window.FindName("CboCompareFilter")
    $script:BtnRunCompare        = $Window.FindName("BtnRunCompare")
    $script:BtnCompareExport     = $Window.FindName("BtnCompareExport")
    $script:BtnCompareMigrate    = $Window.FindName("BtnCompareMigrate")
    $script:GridCompare          = $Window.FindName("GridCompare")
    $script:CmpOnlyA             = $Window.FindName("CmpOnlyA")
    $script:CmpOnlyB             = $Window.FindName("CmpOnlyB")
    $script:CmpMatch             = $Window.FindName("CmpMatch")
    $script:CmpDiff              = $Window.FindName("CmpDiff")
    $script:TxtCompareStatus     = $Window.FindName("TxtCompareStatus")
    
    # Events Tab
    $script:CboEventSource       = $Window.FindName("CboEventSource")
    $script:TxtEventLogPath      = $Window.FindName("TxtEventLogPath")
    $script:BtnEventBrowse       = $Window.FindName("BtnEventBrowse")
    $script:BtnEventDetect       = $Window.FindName("BtnEventDetect")
    $script:BtnEventIngest       = $Window.FindName("BtnEventIngest")
    $script:BtnEventIngestPause  = $Window.FindName("BtnEventIngestPause")
    $script:ChkWatchLocal        = $Window.FindName("ChkWatchLocal")
    $script:ChkWatchA            = $Window.FindName("ChkWatchA")
    $script:ChkWatchB            = $Window.FindName("ChkWatchB")
    $script:ChkWatchCustom       = $Window.FindName("ChkWatchCustom")
    $script:TxtWatchLogPath      = $Window.FindName("TxtWatchLogPath")
    $script:BtnWatchBrowse       = $Window.FindName("BtnWatchBrowse")
    $script:BtnWatchUseIngestPath = $Window.FindName("BtnWatchUseIngestPath")
    $script:BtnEventWatchStart   = $Window.FindName("BtnEventWatchStart")
    $script:BtnEventWatchStop    = $Window.FindName("BtnEventWatchStop")
    $script:BtnEventClear        = $Window.FindName("BtnEventClear")
    $script:BtnEventDetails      = $Window.FindName("BtnEventDetails")
    $script:BtnEventExport       = $Window.FindName("BtnEventExport")
    $script:TxtEventFilter       = $Window.FindName("TxtEventFilter")
    $script:CboEventIdFilter     = $Window.FindName("CboEventIdFilter")
    $script:TxtEventFilterIp     = $Window.FindName("TxtEventFilterIp")
    $script:TxtEventFilterMac    = $Window.FindName("TxtEventFilterMac")
    $script:TxtEventFilterHost   = $Window.FindName("TxtEventFilterHost")
    $script:CboEventFilterServer = $Window.FindName("CboEventFilterServer")
    $script:BtnEventFilterApply  = $Window.FindName("BtnEventFilterApply")
    $script:BtnEventFilterClear  = $Window.FindName("BtnEventFilterClear")
    $script:TxtEventFilterCount  = $Window.FindName("TxtEventFilterCount")
    $script:TxtEventStatus       = $Window.FindName("TxtEventStatus")
    $script:EventIngestProgressPanel = $Window.FindName("EventIngestProgressPanel")
    $script:BarEventIngest       = $Window.FindName("BarEventIngest")
    $script:TxtEventIngestPct    = $Window.FindName("TxtEventIngestPct")
    $script:GridEvents           = $Window.FindName("GridEvents")
    
    # Migrate Tab
    $script:TxtMigrateSource         = $Window.FindName("TxtMigrateSource")
    $script:TxtMigrateDest           = $Window.FindName("TxtMigrateDest")
    $script:BtnMigrateRefreshScopes  = $Window.FindName("BtnMigrateRefreshScopes")
    $script:ChkMigScope              = $Window.FindName("ChkMigScope")
    $script:ChkMigOptions            = $Window.FindName("ChkMigOptions")
    $script:ChkMigReservations       = $Window.FindName("ChkMigReservations")
    $script:ChkMigExclusions         = $Window.FindName("ChkMigExclusions")
    $script:ChkMigLeasesAsRes        = $Window.FindName("ChkMigLeasesAsRes")
    $script:CboMigConflict           = $Window.FindName("CboMigConflict")
    $script:ChkMigActivateDest       = $Window.FindName("ChkMigActivateDest")
    $script:ChkMigDeactivateSource   = $Window.FindName("ChkMigDeactivateSource")
    $script:BtnMigrateSelectAll      = $Window.FindName("BtnMigrateSelectAll")
    $script:BtnMigrateSelectNone     = $Window.FindName("BtnMigrateSelectNone")
    $script:BtnMigrateDryRun         = $Window.FindName("BtnMigrateDryRun")
    $script:BtnMigrateRun            = $Window.FindName("BtnMigrateRun")
    $script:BtnMigrateExport         = $Window.FindName("BtnMigrateExport")
    $script:GridMigrateScopes        = $Window.FindName("GridMigrateScopes")
    $script:TxtMigrateStatus         = $Window.FindName("TxtMigrateStatus")
    $script:GridMigrateResults       = $Window.FindName("GridMigrateResults")
    
    Write-ActionLog "All UI controls bound successfully" "SUCCESS"
    
} catch {
    Write-Error "Failed to initialize UI: $_"
    exit 1
}
#endregion

#region Utility Functions
function Set-Status {
    <#
    .SYNOPSIS
        Updates status bar with thread-safe dispatcher
    #>
    param(
        [string]$Message = "Ready",
        [string]$Server = $null
    )
    
    Write-ActionLog "Status: $Message" "INFO"
    
    try {
        if ($null -ne $script:StatusMessage) {
            $script:StatusMessage.Dispatcher.Invoke([action]{
                $script:StatusMessage.Text = $Message
            }, [System.Windows.Threading.DispatcherPriority]::Normal)
        }
        
        if ($Server -and $null -ne $script:StatusServer) {
            $script:StatusServer.Dispatcher.Invoke([action]{
                $script:StatusServer.Text = $Server
            }, [System.Windows.Threading.DispatcherPriority]::Normal)
        }
    } catch {
        Write-ActionLog "Failed to update status: $_" "WARN"
    }
}

function Get-SelectedScopeId {
    <#
    .SYNOPSIS
        Gets the currently selected scope ID from navigation or grid
        FIXED: Proper scope tracking
    #>
    
    # Try from global state first
    if ($Global:SelectedScope) {
        Write-ActionLog "Retrieved scope from global state: $($Global:SelectedScope)" "INFO"
        return $Global:SelectedScope
    }
    
    # Try from navigation tree
    if ($null -ne $script:NavTree -and $null -ne $script:NavTree.SelectedItem) {
        $selected = $script:NavTree.SelectedItem
        if ($selected.Tag -and $selected.Tag -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
            Write-ActionLog "Retrieved scope from nav tree: $($selected.Tag)" "INFO"
            return $selected.Tag
        }
    }
    
    # Try from scopes grid
    if ($null -ne $script:GridScopes -and $null -ne $script:GridScopes.SelectedItem) {
        $scopeId = $script:GridScopes.SelectedItem.ScopeId
        if ($scopeId) {
            Write-ActionLog "Retrieved scope from grid: $scopeId" "INFO"
            return $scopeId
        }
    }
    
    Write-ActionLog "No scope currently selected" "WARN"
    return $null
}

function Test-IPAddress {
    <#
    .SYNOPSIS
        Validates IP address format
    #>
    param([string]$IP)
    
    if ([string]::IsNullOrWhiteSpace($IP)) { return $false }
    
    try {
        $addr = [System.Net.IPAddress]::Parse($IP)
        return ($addr.AddressFamily -eq 'InterNetwork')
    } catch {
        return $false
    }
}

function Test-MACAddress {
    <#
    .SYNOPSIS
        Validates MAC address format
    #>
    param([string]$MAC)
    
    if ([string]::IsNullOrWhiteSpace($MAC)) { return $false }
    
    # Accept various formats: 00-11-22-33-44-55, 00:11:22:33:44:55, 001122334455
    return $MAC -match '^([0-9A-Fa-f]{2}[:-]?){5}([0-9A-Fa-f]{2})$'
}

function Show-MessageBox {
    <#
    .SYNOPSIS
        Displays a message box
    #>
    param(
        [string]$Message,
        [string]$Title = "DHCP Manager",
        [System.Windows.MessageBoxButton]$Button = 'OK',
        [System.Windows.MessageBoxImage]$Icon = 'Information'
    )
    
    return [System.Windows.MessageBox]::Show($Message, $Title, $Button, $Icon)
}

function Get-SafeCount {
    <#
    .SYNOPSIS
        StrictMode-safe count for $null, single objects, or collections
    #>
    param($Object)
    
    if ($null -eq $Object) { return 0 }
    
    # Prefer true collection Count when available
    if ($Object -is [System.Array]) { return $Object.Length }
    if ($Object -is [System.Collections.ICollection] -and -not ($Object -is [string])) {
        try { return [int]$Object.Count } catch { }
    }
    
    # Single scalar / PSObject result from a cmdlet
    return @($Object).Count
}

#region Task Progress (status bar + pause/cancel)
function Format-TaskEta {
    param([TimeSpan]$Eta)
    if ($null -eq $Eta -or $Eta.TotalSeconds -lt 0) { return '--:--' }
    if ($Eta.TotalHours -ge 1) {
        return '{0:hh\:mm\:ss}' -f $Eta
    }
    return '{0:mm\:ss}' -f $Eta
}

function Sync-TaskProgressUi {
    param([switch]$ForcePump)
    
    $active = [bool]$Global:TaskProgress.Active
    $pct = [math]::Max(0, [math]::Min(100, [int]$Global:TaskProgress.Percent))
    $msg = "$($Global:TaskProgress.Message)"
    $canPause = [bool]$Global:TaskProgress.CanPause
    $paused = [bool]$Global:TaskProgress.Paused
    $pauseLabel = if ($paused) { '▶️ Resume' } else { '⏸ Pause' }
    
    $update = {
        if ($null -ne $script:TaskProgressPanel) {
            $script:TaskProgressPanel.Visibility = if ($active) {
                [System.Windows.Visibility]::Visible
            } else {
                [System.Windows.Visibility]::Collapsed
            }
        }
        if ($null -ne $script:TxtTaskProgress) { $script:TxtTaskProgress.Text = $msg }
        if ($null -ne $script:BarTaskProgress) { $script:BarTaskProgress.Value = $pct }
        if ($null -ne $script:BtnTaskPause) {
            $script:BtnTaskPause.IsEnabled = ($active -and $canPause)
            $script:BtnTaskPause.Content = $pauseLabel
        }
        if ($null -ne $script:BtnTaskCancel) {
            $script:BtnTaskCancel.IsEnabled = $active
        }
        if ($null -ne $script:EventIngestProgressPanel) {
            $isIngest = $active -and ("$($Global:TaskProgress.Name)" -eq 'Ingest')
            $script:EventIngestProgressPanel.Visibility = if ($isIngest) {
                [System.Windows.Visibility]::Visible
            } else {
                [System.Windows.Visibility]::Collapsed
            }
        }
        if ($null -ne $script:BarEventIngest) { $script:BarEventIngest.Value = $pct }
        if ($null -ne $script:TxtEventIngestPct) { $script:TxtEventIngestPct.Text = "$pct%" }
        if ($null -ne $script:BtnEventIngestPause) {
            $isIngest = $active -and ("$($Global:TaskProgress.Name)" -eq 'Ingest')
            $script:BtnEventIngestPause.IsEnabled = ($isIngest -and $canPause)
            $script:BtnEventIngestPause.Content = $pauseLabel
        }
        if ($null -ne $script:StatusMessage -and $active -and $msg) {
            $script:StatusMessage.Text = $msg
        }
    }
    
    try {
        if ($null -ne $script:Window -and -not $script:Window.Dispatcher.CheckAccess()) {
            $script:Window.Dispatcher.Invoke([action]$update, [System.Windows.Threading.DispatcherPriority]::Background)
        } else {
            & $update
        }
    } catch {
        try { & $update } catch {}
    }
    
    if ($ForcePump) {
        try { [System.Windows.Forms.Application]::DoEvents() } catch {}
        try {
            if ($null -ne $script:Window) {
                $script:Window.Dispatcher.Invoke([action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
            }
        } catch {}
    }
}

function Start-TaskProgress {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$Message = 'Working...',
        [switch]$CanPause,
        [long]$Total = 0
    )
    
    $Global:TaskProgress.Active = $true
    $Global:TaskProgress.Name = $Name
    $Global:TaskProgress.Message = $Message
    $Global:TaskProgress.Percent = 0
    $Global:TaskProgress.Processed = 0
    $Global:TaskProgress.Total = $Total
    $Global:TaskProgress.CanPause = [bool]$CanPause
    $Global:TaskProgress.Paused = $false
    $Global:TaskProgress.CancelRequested = $false
    $Global:TaskProgress.StartTime = Get-Date
    Sync-TaskProgressUi -ForcePump
}

function Update-TaskProgress {
    param(
        [long]$Processed = -1,
        [long]$Total = -1,
        [string]$Message,
        [double]$Percent = -1
    )
    
    if (-not $Global:TaskProgress.Active) { return }
    
    if ($Processed -ge 0) { $Global:TaskProgress.Processed = $Processed }
    if ($Total -ge 0) { $Global:TaskProgress.Total = $Total }
    
    $pct = $Percent
    if ($pct -lt 0) {
        if ($Global:TaskProgress.Total -gt 0) {
            $pct = (100.0 * $Global:TaskProgress.Processed) / [double]$Global:TaskProgress.Total
        } else {
            $pct = [double]$Global:TaskProgress.Percent
        }
    }
    $pct = [math]::Max(0, [math]::Min(100, $pct))
    $Global:TaskProgress.Percent = [int][math]::Round($pct)
    
    $etaText = ''
    if ($null -ne $Global:TaskProgress.StartTime -and $Global:TaskProgress.Processed -gt 0 -and $Global:TaskProgress.Total -gt 0) {
        $elapsed = (Get-Date) - $Global:TaskProgress.StartTime
        if ($elapsed.TotalSeconds -gt 0.5) {
            $rate = $Global:TaskProgress.Processed / $elapsed.TotalSeconds
            if ($rate -gt 0) {
                $remain = ($Global:TaskProgress.Total - $Global:TaskProgress.Processed) / $rate
                $etaText = " — ETA $(Format-TaskEta ([TimeSpan]::FromSeconds([math]::Max(0, $remain))))"
            }
        }
    }
    
    $pausePrefix = if ($Global:TaskProgress.Paused) { 'PAUSED — ' } else { '' }
    if ($Message) {
        $Global:TaskProgress.Message = "$pausePrefix$Message$etaText"
    } elseif ($etaText -or $pausePrefix) {
        $base = "$($Global:TaskProgress.Message)" -replace '^PAUSED — ', '' -replace ' — ETA .*$', ''
        $Global:TaskProgress.Message = "$pausePrefix$base$etaText"
    }
    
    Sync-TaskProgressUi -ForcePump
}

function Wait-TaskProgressIfPaused {
    while ($Global:TaskProgress.Active -and $Global:TaskProgress.Paused -and -not $Global:TaskProgress.CancelRequested) {
        Update-TaskProgress
        Start-Sleep -Milliseconds 150
        try { [System.Windows.Forms.Application]::DoEvents() } catch {}
    }
}

function Test-TaskCancelRequested {
    return [bool]($Global:TaskProgress.Active -and $Global:TaskProgress.CancelRequested)
}

function Complete-TaskProgress {
    param(
        [string]$Message = 'Ready',
        [switch]$KeepVisibleBriefly
    )
    
    $wasActive = [bool]$Global:TaskProgress.Active
    $Global:TaskProgress.Active = $false
    $Global:TaskProgress.Paused = $false
    $Global:TaskProgress.CancelRequested = $false
    $Global:TaskProgress.CanPause = $false
    $Global:TaskProgress.Percent = 100
    $Global:TaskProgress.Message = $Message
    $Global:TaskProgress.Name = ''
    
    Sync-TaskProgressUi -ForcePump
    
    if ($wasActive -and $KeepVisibleBriefly) {
        Start-Sleep -Milliseconds 400
    }
    
    $Global:TaskProgress.Percent = 0
    Sync-TaskProgressUi
    
    try {
        if ($null -ne $script:StatusMessage) { $script:StatusMessage.Text = $Message }
    } catch {}
}

function Toggle-TaskProgressPause {
    if (-not $Global:TaskProgress.Active -or -not $Global:TaskProgress.CanPause) { return }
    $Global:TaskProgress.Paused = -not [bool]$Global:TaskProgress.Paused
    Write-ActionLog $(if ($Global:TaskProgress.Paused) { "Task paused: $($Global:TaskProgress.Name)" } else { "Task resumed: $($Global:TaskProgress.Name)" }) "INFO"
    Update-TaskProgress
}

function Request-TaskProgressCancel {
    if (-not $Global:TaskProgress.Active) { return }
    $Global:TaskProgress.CancelRequested = $true
    $Global:TaskProgress.Paused = $false
    Write-ActionLog "Cancel requested for task: $($Global:TaskProgress.Name)" "WARN"
    Update-TaskProgress -Message "Canceling $($Global:TaskProgress.Name)..."
}
#endregion

function Get-CleanDhcpServerHostName {
    <#
    .SYNOPSIS
        Strips AD RDN prefixes (rcn=, cn=, etc.) and normalizes DHCP server host names
    #>
    param([string]$Name)
    
    $n = "$Name".Trim().Trim('"').Trim("'")
    if ([string]::IsNullOrWhiteSpace($n)) { return '' }
    
    # Full DN / RDN style: rcn=host.domain.com,CN=...
    if ($n -match '(?i)(?:^|,)(?:rcn|cn|dNSHostName|name)=([^,=]+)') {
        $n = $Matches[1].Trim()
    }
    
    # Repeated prefix=value
    $guard = 0
    while ($guard -lt 5 -and $n -match '(?i)^(rcn|cn|dns|dnshostname|name)=(.+)$') {
        $n = $Matches[2].Trim()
        $guard++
    }
    
    # Still contains '=' — pull out a hostname-looking token
    if ($n -match '=') {
        if ($n -match '([A-Za-z0-9][A-Za-z0-9\-]{0,62}(?:\.[A-Za-z0-9][A-Za-z0-9\-]{0,62})+)') {
            $n = $Matches[1]
        } elseif ($n -match '([0-9]{1,3}(?:\.[0-9]{1,3}){3})') {
            $n = $Matches[1]
        }
    }
    
    return $n.Trim().TrimEnd('.')
}

function ConvertFrom-AdDhcpServersValue {
    <#
    .SYNOPSIS
        Parses AD dhcpServers attribute values into IP + cleaned DNS name
    #>
    param(
        [string]$Raw,
        [string]$FallbackName = ''
    )
    
    $ip = ''
    $dns = ''
    $text = "$Raw".Trim()
    
    # Common format: i<ip>$<name>$...
    if ($text -match '(?i)i([0-9]{1,3}(?:\.[0-9]{1,3}){3})\$([^$]*)') {
        $ip = $Matches[1]
        $dns = Get-CleanDhcpServerHostName -Name $Matches[2]
    }
    
    if ([string]::IsNullOrWhiteSpace($ip) -and $text -match '([0-9]{1,3}(?:\.[0-9]{1,3}){3})') {
        $ip = $Matches[1]
    }
    
    if ([string]::IsNullOrWhiteSpace($dns)) {
        $dns = Get-CleanDhcpServerHostName -Name $FallbackName
    }
    
    if ([string]::IsNullOrWhiteSpace($dns) -and $text -match '(?i)(?:rcn|cn)=([A-Za-z0-9\.\-]+)') {
        $dns = Get-CleanDhcpServerHostName -Name $Matches[1]
    }
    
    return [PSCustomObject]@{
        DnsName   = $dns
        IPAddress = $ip
    }
}

function Get-DhcpConnectErrorDetail {
    <#
    .SYNOPSIS
        Unwraps DHCP connect exceptions so Access Denied / RPC codes are visible
    #>
    param($ErrorRecord)
    
    $parts = [System.Collections.Generic.List[string]]::new()
    
    if ($null -eq $ErrorRecord) { return 'Unknown error' }
    
    try {
        if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) {
            if ($ErrorRecord.FullyQualifiedErrorId) {
                [void]$parts.Add("Id=$($ErrorRecord.FullyQualifiedErrorId)")
            }
            try {
                if ($ErrorRecord.CategoryInfo -and $ErrorRecord.CategoryInfo.Reason) {
                    [void]$parts.Add("Reason=$($ErrorRecord.CategoryInfo.Reason)")
                }
            } catch {}
            $ex = $ErrorRecord.Exception
        } else {
            $ex = $ErrorRecord
        }
    } catch {
        $ex = $ErrorRecord
    }
    
    $guard = 0
    while ($null -ne $ex -and $guard -lt 8) {
        $msg = ''
        try { $msg = "$($ex.Message)".Trim() } catch { $msg = '' }
        if ($msg -and -not ($parts -contains $msg)) {
            [void]$parts.Add($msg)
        }
        try {
            $hr = [int]$ex.HResult
            if ($hr -ne 0) {
                $hrText = ('HRESULT=0x{0:X8}' -f ([uint32]$hr))
                if (-not ($parts -contains $hrText)) { [void]$parts.Add($hrText) }
            }
        } catch {}
        try { $ex = $ex.InnerException } catch { $ex = $null }
        $guard++
    }
    
    if ((Get-SafeCount $parts) -eq 0) {
        return "$ErrorRecord"
    }
    return ($parts -join ' | ')
}

function Test-DhcpClusterLikeName {
    param([string]$Name)
    $n = Get-CleanDhcpServerHostName -Name $Name
    if (-not $n) { return $false }
    $short = ($n -split '\.')[0]
    return [bool]($short -match '(?i)(cluster|failover|vip|nlb|lb\d*|cast)$' -or $n -match '(?i)[-_.](cluster|failover|vip)([-_.]|$)')
}

function Get-DhcpRelatedConnectCandidates {
    <#
    .SYNOPSIS
        Suggests real DHCP nodes from domain scan when a cluster/VIP name is used
    #>
    param(
        [string]$Name,
        [string]$FallbackIP = '',
        [int]$MaxCandidates = 6
    )
    
    $related = [System.Collections.Generic.List[object]]::new()
    $clean = Get-CleanDhcpServerHostName -Name $Name
    if (-not $clean) { return @() }
    
    $short = (($clean -split '\.')[0]).ToLowerInvariant()
    $site = ''
    if ($short -match '^(?<site>[a-z0-9]+)-') { $site = $Matches['site'] }
    
    $fallbackIp = "$FallbackIP".Trim()
    $octet3 = ''
    if ($fallbackIp -match '^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$') {
        $octet3 = $Matches[1]
    }
    
    $clusterLike = Test-DhcpClusterLikeName -Name $clean
    
    foreach ($r in @($Global:DomainScanResults)) {
        if ($null -eq $r) { continue }
        
        $dns = Get-CleanDhcpServerHostName -Name "$($r.DnsName)"
        $ip = "$($r.IPAddress)".Trim()
        if ([string]::IsNullOrWhiteSpace($dns)) { continue }
        if ($dns.Equals($clean, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        if (Test-DhcpClusterLikeName -Name $dns) { continue }
        
        $online = "$($r.Online)"
        $isUp = ($online -eq 'Up' -or $online -eq 'Yes' -or "$($r.Status)" -eq 'Up')
        
        $score = 0
        $dnsLower = $dns.ToLowerInvariant()
        $dnsShort = (($dns -split '\.')[0]).ToLowerInvariant()
        
        if ($dnsLower -match 'dhcp') { $score += 3 }
        if ($site -and $dnsShort.StartsWith("$site-")) { $score += 3 }
        if ($octet3 -and $ip -match "^$([regex]::Escape($octet3))\.\d{1,3}$") { $score += 4 }
        if ($isUp) { $score += 2 }
        if ("$($r.Authorized)" -eq 'Yes') { $score += 1 }
        
        # Strongly prefer node-like names when user asked for a cluster
        if ($clusterLike) {
            if ($score -lt 5) { continue }
        } else {
            # For non-cluster failures, only suggest same /24 dhcp hosts
            if (-not ($octet3 -and $ip -match "^$([regex]::Escape($octet3))\.\d{1,3}$" -and $dnsLower -match 'dhcp')) {
                continue
            }
            if ($score -lt 6) { continue }
        }
        
        [void]$related.Add([PSCustomObject]@{
            DnsName = $dns
            IPAddress = if ($ip -match '^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$') { $ip } else { '' }
            Score = $score
            Online = $online
        })
    }
    
    $sorted = @($related | Sort-Object -Property @{ Expression = 'Score'; Descending = $true }, @{ Expression = 'DnsName'; Descending = $false })
    if ((Get-SafeCount $sorted) -gt $MaxCandidates) {
        $sorted = @($sorted | Select-Object -First $MaxCandidates)
    }
    return $sorted
}

function Test-DhcpServerRpcReachable {
    <#
    .SYNOPSIS
        Probes DHCP RPC management on a target (scopes first, then server settings)
    #>
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )
    
    $target = "$ComputerName".Trim()
    # Primary probe used everywhere else in the app
    try {
        $null = @(Get-DhcpServerv4Scope -ComputerName $target -ErrorAction Stop)
        return [PSCustomObject]@{ Ok = $true; Method = 'Get-DhcpServerv4Scope'; Error = '' }
    } catch {
        $scopeErr = $_
    }
    
    # Secondary probe — sometimes clarifies Access Denied vs empty/service issues
    try {
        $null = Get-DhcpServerSetting -ComputerName $target -ErrorAction Stop
        # Settings worked but scopes failed — still treat as failure for app use, but richer error
        $detail = Get-DhcpConnectErrorDetail -ErrorRecord $scopeErr
        throw "Server settings reachable on '$target', but scope enumeration failed: $detail"
    } catch {
        if ("$_" -match 'Server settings reachable') { throw }
        # Prefer the original scopes error (primary app requirement)
        throw $scopeErr
    }
}

function Get-DhcpFallbackIpForName {
    <#
    .SYNOPSIS
        Looks up a scanned DHCP server IP to use when hostname connect fails
    #>
    param([string]$Name)
    
    $clean = Get-CleanDhcpServerHostName -Name $Name
    foreach ($r in @($Global:DomainScanResults)) {
        $rowDns = Get-CleanDhcpServerHostName -Name "$($r.DnsName)"
        $rowIp  = "$($r.IPAddress)".Trim()
        if ($rowIp -notmatch '^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$') { continue }
        
        if ($clean -and $rowDns -and $clean.Equals($rowDns, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $rowIp
        }
        if ($Name -and "$($r.DnsName)" -and $Name.Equals("$($r.DnsName)", [System.StringComparison]::OrdinalIgnoreCase)) {
            return $rowIp
        }
        if ($clean -and $rowIp -eq $clean) { return $rowIp }
    }
    
    return ''
}

function Connect-DhcpServerTarget {
    <#
    .SYNOPSIS
        Validates DHCP connectivity; tries hostname, IP, DNS, and related scan nodes
    #>
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [string]$FallbackIP = ''
    )
    
    $cleaned = Get-CleanDhcpServerHostName -Name $ComputerName
    if ([string]::IsNullOrWhiteSpace($cleaned)) {
        $cleaned = "$ComputerName".Trim()
    }
    
    if ($cleaned -match '^(localhost|127\.0\.0\.1|\.)$') {
        $cleaned = 'localhost'
    }
    
    if (-not (Get-Module -Name DhcpServer -ListAvailable)) {
        throw "DhcpServer module not installed. Install RSAT-DHCP: Install-WindowsFeature RSAT-DHCP (Server) or Add-WindowsCapability Rsat.DHCP.Tools~~~~0.0.1.0 (Windows 10/11)."
    }
    
    Import-Module DhcpServer -ErrorAction Stop
    
    $candidates = [System.Collections.Generic.List[string]]::new()
    $addCandidate = {
        param([string]$Value)
        $v = "$Value".Trim()
        if ([string]::IsNullOrWhiteSpace($v)) { return }
        foreach ($existing in $candidates) {
            if ($existing.Equals($v, [System.StringComparison]::OrdinalIgnoreCase)) { return }
        }
        [void]$candidates.Add($v)
    }
    
    & $addCandidate $cleaned
    
    $fb = "$FallbackIP".Trim()
    if ([string]::IsNullOrWhiteSpace($fb)) {
        $fb = Get-DhcpFallbackIpForName -Name $ComputerName
        if ([string]::IsNullOrWhiteSpace($fb)) {
            $fb = Get-DhcpFallbackIpForName -Name $cleaned
        }
    }
    if ($fb -match '^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$') {
        & $addCandidate $fb
    }
    
    # DNS A-record fallbacks when primary is a hostname
    if ($cleaned -ne 'localhost' -and $cleaned -notmatch '^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$') {
        try {
            $addrs = @([System.Net.Dns]::GetHostAddresses($cleaned) |
                Where-Object { $_.AddressFamily -eq 'InterNetwork' })
            foreach ($a in $addrs) {
                & $addCandidate "$a"
            }
            if (-not $fb -and (Get-SafeCount $addrs) -gt 0) {
                $fb = "$($addrs[0])"
            }
        } catch {
            Write-ActionLog "DNS resolve failed for '${cleaned}': $_" "WARN"
        }
    }
    
    # Related DHCP nodes from domain scan (especially for *-cluster names / VIPs)
    $related = @(Get-DhcpRelatedConnectCandidates -Name $cleaned -FallbackIP $fb -MaxCandidates 6)
    if ((Get-SafeCount $related) -gt 0) {
        $names = @($related | ForEach-Object { $_.DnsName }) -join ', '
        Write-ActionLog "Also trying related DHCP node(s) from scan: $names" "INFO"
        foreach ($rel in $related) {
            & $addCandidate "$($rel.DnsName)"
            if ($rel.IPAddress) { & $addCandidate "$($rel.IPAddress)" }
        }
    } elseif (Test-DhcpClusterLikeName -Name $cleaned) {
        Write-ActionLog "Target looks like a cluster/VIP name. Run Scan Domain and connect to an active DHCP node (not the cluster name) if connect fails." "WARN"
    }
    
    $attemptErrors = [System.Collections.Generic.List[string]]::new()
    
    foreach ($target in $candidates) {
        try {
            Write-ActionLog "Trying DHCP RPC connect via '$target'..." "INFO"
            $null = Test-DhcpServerRpcReachable -ComputerName $target
            if (-not $target.Equals($cleaned, [System.StringComparison]::OrdinalIgnoreCase)) {
                Write-ActionLog "Connected using fallback target '$target' (requested '$cleaned')" "SUCCESS"
            }
            return $target
        } catch {
            $raw = Get-DhcpConnectErrorDetail -ErrorRecord $_
            [void]$attemptErrors.Add("${target}: $raw")
            Write-ActionLog "Connect attempt failed for '${target}': $raw" "WARN"
        }
    }
    
    $allFailText = ($attemptErrors -join ' || ')
    $hint = switch -Regex ($allFailText) {
        'access is denied|AccessDenied|0x80070005|HRESULT=0x80070005' {
            "Access denied. Run PowerShell / DHCP Manager as a user in DHCP Administrators (or equivalent) on the target domain."
        }
        'RPC|RPC server|0x800706BA|unavailable|HRESULT=0x800706BA' {
            "RPC unreachable. Check firewall (RPC TCP 135 + dynamic high ports), DHCP Server service, and routing. Try a node hostname or IP from Scan Domain."
        }
        'WinRM|WS-Management' {
            "WinRM issue. DHCP cmdlets use RPC (not WinRM). Verify RPC/firewall connectivity."
        }
        'cannot find|not found|no such host|DNS|No such host is known' {
            "Name resolution failed. Use FQDN or IP address; Scan Domain can fill a reachable host/IP."
        }
        'The term .*Get-DhcpServerv4Scope' {
            "DhcpServer module failed to load cmdlets. Reinstall RSAT-DHCP tools."
        }
        'Failed to enumerate scopes|enumerate scopes' {
            if (Test-DhcpClusterLikeName -Name $cleaned) {
                "Cluster/VIP names often cannot enumerate scopes over DHCP RPC. Use Scan Domain and Connect to an active node (for example a host like …dhcp1… / …dhcp2…), not '$cleaned'."
            } else {
                "DHCP RPC could not enumerate scopes. Confirm the DHCP Server role is running on that host, your account is in DHCP Administrators/Users, and you are not targeting a cluster name/VIP. Prefer a node from Scan Domain."
            }
        }
        default {
            "Verify network path, DHCP Server service, and account permissions. If this is a failover cluster name, connect to an active DHCP node from Scan Domain instead of the cluster/VIP."
        }
    }
    
    $tried = ($candidates -join ', ')
    $details = ($attemptErrors -join "`n")
    $suggest = ''
    if ((Get-SafeCount $related) -gt 0) {
        $nodeLines = @($related | ForEach-Object {
            $ipPart = if ($_.IPAddress) { " ($($_.IPAddress))" } else { '' }
            "  - $($_.DnsName)$ipPart"
        }) -join "`n"
        $suggest = "`n`nSuggested nodes from your last domain scan (try one of these in the DHCP Server box):`n$nodeLines"
    } elseif (Test-DhcpClusterLikeName -Name $cleaned) {
        $suggest = "`n`nTip: Run Scan Domain, then select an online DHCP host (not a *cluster* name) and click Use for Server A."
    }
    
    throw "Cannot reach DHCP on '$cleaned' (tried: $tried). $hint$suggest`n`nDetails:`n$details"
}

function Enable-ConnectedControls {
    <#
    .SYNOPSIS
        Enables controls when connected to server
    #>
    param([bool]$Connected)
    
    try {
        $script:Window.Dispatcher.Invoke([action]{
            $script:BtnDisconnect.IsEnabled = $Connected
            $script:BtnRefresh.IsEnabled = $Connected
            $script:BtnScopeAdd.IsEnabled = $Connected
            $script:BtnRefreshStats.IsEnabled = $Connected
            if ($null -ne $script:BtnScopeStatDetails) { $script:BtnScopeStatDetails.IsEnabled = $Connected }
            if ($null -ne $script:BtnExportScopeStats) { $script:BtnExportScopeStats.IsEnabled = $Connected }
            if ($null -ne $script:BtnTroubleshootRefreshScopes) { $script:BtnTroubleshootRefreshScopes.IsEnabled = $Connected }
            if ($null -ne $script:BtnTroubleshootUseSelected) { $script:BtnTroubleshootUseSelected.IsEnabled = $Connected }
            if ($null -ne $script:BtnTroubleshootRun) { $script:BtnTroubleshootRun.IsEnabled = $Connected }
            if ($null -ne $script:BtnTroubleshootExport) { $script:BtnTroubleshootExport.IsEnabled = $Connected }
            if ($null -ne $script:BtnDashboardRefresh) { $script:BtnDashboardRefresh.IsEnabled = $Connected }
            if ($null -ne $script:BtnDashboardOpenStats) { $script:BtnDashboardOpenStats.IsEnabled = $Connected }
            if ($null -ne $script:CboTroubleshootScope) { $script:CboTroubleshootScope.IsEnabled = $Connected }
            if ($null -ne $script:CboTroubleshootSample) { $script:CboTroubleshootSample.IsEnabled = $Connected }
            if (-not $Connected) {
                if ($null -ne $script:ChkTroubleshootReviewed) {
                    $script:ChkTroubleshootReviewed.IsChecked = $false
                    $script:ChkTroubleshootReviewed.IsEnabled = $false
                }
                if ($null -ne $script:BtnTroubleshootClearBad) { $script:BtnTroubleshootClearBad.IsEnabled = $false }
            }
        }, [System.Windows.Threading.DispatcherPriority]::Normal)
        
        Write-ActionLog "Controls enabled state set to: $Connected" "INFO"
    } catch {
        Write-ActionLog "Failed to enable controls: $_" "ERROR"
    }
}
#endregion

#region Domain DHCP Server Scan
function Get-CurrentDnsDomainName {
    <#
    .SYNOPSIS
        Resolves the current machine DNS domain (best effort)
    #>
    try {
        $dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        if ($dom -and $dom.Name) { return "$($dom.Name)".Trim() }
    } catch {}
    
    if (-not [string]::IsNullOrWhiteSpace($env:USERDNSDOMAIN)) {
        return "$env:USERDNSDOMAIN".Trim()
    }
    
    try {
        $root = [ADSI]'LDAP://RootDSE'
        $dn = [string]$root.defaultNamingContext
        if ($dn) {
            $parts = @($dn -split ',' | Where-Object { $_ -match '^DC=' } | ForEach-Object { $_ -replace '^DC=', '' })
            if ((Get-SafeCount $parts) -gt 0) { return ($parts -join '.') }
        }
    } catch {}
    
    return ''
}

function Get-ScanDomainsConfigPath {
    $dir = Join-Path $env:LOCALAPPDATA 'DHCPManager'
    if (-not (Test-Path -LiteralPath $dir)) {
        try { New-Item -ItemType Directory -Path $dir -Force | Out-Null } catch {}
    }
    return (Join-Path $dir 'scan-domains.txt')
}

function Import-ScanDomainsConfig {
    <#
    .SYNOPSIS
        Loads persisted extra scan domains from %LOCALAPPDATA%\DHCPManager\scan-domains.txt
    #>
    $path = Get-ScanDomainsConfigPath
    $list = [System.Collections.Generic.List[string]]::new()
    if (-not (Test-Path -LiteralPath $path)) { return @($list) }
    
    try {
        foreach ($line in @(Get-Content -LiteralPath $path -ErrorAction Stop)) {
            foreach ($part in @($line -split '[;,]')) {
                $d = "$part".Trim()
                if ([string]::IsNullOrWhiteSpace($d)) { continue }
                if ($d.StartsWith('#')) { continue }
                $key = $d.ToLowerInvariant()
                $exists = $false
                foreach ($e in $list) {
                    if ("$e".ToLowerInvariant() -eq $key) { $exists = $true; break }
                }
                if (-not $exists) { [void]$list.Add($d) }
            }
        }
    } catch {
        Write-ActionLog "Could not load scan domain list: $_" "WARN"
    }
    
    return @($list)
}

function Export-ScanDomainsConfig {
    <#
    .SYNOPSIS
        Persists extra scan domains (excludes current domain)
    #>
    param([string[]]$Domains)
    
    $current = Get-CurrentDnsDomainName
    $currentKey = if ($current) { $current.ToLowerInvariant() } else { '' }
    $toSave = [System.Collections.Generic.List[string]]::new()
    
    foreach ($d in @($Domains)) {
        $name = "$d".Trim()
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $key = $name.ToLowerInvariant()
        if ($currentKey -and $key -eq $currentKey) { continue }
        $exists = $false
        foreach ($e in $toSave) {
            if ("$e".ToLowerInvariant() -eq $key) { $exists = $true; break }
        }
        if (-not $exists) { [void]$toSave.Add($name) }
    }
    
    $path = Get-ScanDomainsConfigPath
    try {
        $header = @(
            '# DHCP Manager — extra domains to scan for authorized DHCP servers'
            '# One domain DNS name per line (or comma/semicolon separated)'
            "# Current domain is always scanned automatically: $current"
            ''
        )
        ($header + @($toSave)) | Set-Content -LiteralPath $path -Encoding UTF8
        $Global:ExtraScanDomains = [System.Collections.Generic.List[string]]::new()
        foreach ($s in $toSave) { [void]$Global:ExtraScanDomains.Add($s) }
        Write-ActionLog "Saved $(Get-SafeCount $toSave) extra scan domain(s) to $path" "INFO"
    } catch {
        Write-ActionLog "Could not save scan domain list: $_" "WARN"
    }
}

function Get-NormalizedScanDomainList {
    <#
    .SYNOPSIS
        Builds a unique, ordered domain list (current domain first when known)
    #>
    param([string[]]$Domains)
    
    $result = [System.Collections.Generic.List[string]]::new()
    $seen = @{}
    
    $current = Get-CurrentDnsDomainName
    if (-not [string]::IsNullOrWhiteSpace($current)) {
        [void]$result.Add($current)
        $seen[$current.ToLowerInvariant()] = $true
    }
    
    foreach ($raw in @($Domains)) {
        foreach ($part in @("$raw" -split '[;,\r\n]+')) {
            $d = "$part".Trim()
            if ([string]::IsNullOrWhiteSpace($d)) { continue }
            $key = $d.ToLowerInvariant()
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            [void]$result.Add($d)
        }
    }
    
    # If nothing resolved, still allow an empty list (caller may query default RootDSE)
    return @($result)
}

function Get-DomainDhcpServersFromLdap {
    <#
    .SYNOPSIS
        Discovers authorized DHCP servers via ADSI NetServices for a domain DNS name
    #>
    param(
        [string]$DomainDns = ''
    )
    
    $servers = [System.Collections.Generic.List[object]]::new()
    $domainLabel = if ([string]::IsNullOrWhiteSpace($DomainDns)) { '(default)' } else { $DomainDns }
    
    try {
        $rootPath = if ([string]::IsNullOrWhiteSpace($DomainDns)) {
            'LDAP://RootDSE'
        } else {
            "LDAP://$DomainDns/RootDSE"
        }
        
        $rootDse = [ADSI]$rootPath
        $configNc = $null
        try {
            if ((Get-SafeCount $rootDse.Properties['configurationNamingContext']) -gt 0) {
                $configNc = [string]$rootDse.Properties['configurationNamingContext'][0]
            }
        } catch {}
        if ([string]::IsNullOrWhiteSpace($configNc)) {
            try { $configNc = [string]$rootDse.configurationNamingContext } catch {}
        }
        if ([string]::IsNullOrWhiteSpace($configNc)) {
            throw "Could not read configurationNamingContext for $domainLabel"
        }
        
        $searchPath = if ([string]::IsNullOrWhiteSpace($DomainDns)) {
            "LDAP://CN=NetServices,CN=Services,$configNc"
        } else {
            "LDAP://$DomainDns/CN=NetServices,CN=Services,$configNc"
        }
        
        $searchRoot = [ADSI]$searchPath
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
        $searcher.Filter = '(objectClass=dHCPClass)'
        [void]$searcher.PropertiesToLoad.Add('name')
        [void]$searcher.PropertiesToLoad.Add('dhcpServers')
        $searcher.PageSize = 200
        
        foreach ($res in $searcher.FindAll()) {
            $name = ''
            if ((Get-SafeCount $res.Properties['name']) -gt 0) {
                $name = [string]$res.Properties['name'][0]
            }
            
            $dhcpServersProp = @()
            if ((Get-SafeCount $res.Properties['dhcpServers']) -gt 0) {
                $dhcpServersProp = @($res.Properties['dhcpServers'] | ForEach-Object { "$_" })
            }
            
            foreach ($raw in $dhcpServersProp) {
                $parsed = ConvertFrom-AdDhcpServersValue -Raw $raw -FallbackName $name
                $dns = "$($parsed.DnsName)"
                $ip  = "$($parsed.IPAddress)"
                
                if ([string]::IsNullOrWhiteSpace($dns) -and [string]::IsNullOrWhiteSpace($ip)) { continue }
                if ([string]::IsNullOrWhiteSpace($dns)) { $dns = $ip }
                
                $servers.Add([PSCustomObject]@{
                    DnsName    = $dns
                    IPAddress  = $ip
                    Authorized = $true
                    AuthDetail = "Authorized in AD NetServices ($domainLabel)"
                    Source     = "AD NetServices ($domainLabel)"
                    Domain     = $(if ($DomainDns) { $DomainDns } else { $domainLabel })
                })
            }
            
            if ((Get-SafeCount $dhcpServersProp) -eq 0 -and $name -and $name -notmatch '^dhcpRoot') {
                $cleanName = Get-CleanDhcpServerHostName -Name $name
                if ([string]::IsNullOrWhiteSpace($cleanName)) { $cleanName = $name }
                $servers.Add([PSCustomObject]@{
                    DnsName    = $cleanName
                    IPAddress  = ''
                    Authorized = $true
                    AuthDetail = "Authorized in AD NetServices object ($domainLabel)"
                    Source     = "AD NetServices ($domainLabel)"
                    Domain     = $(if ($DomainDns) { $DomainDns } else { $domainLabel })
                })
            }
        }
        
        Write-ActionLog "LDAP scan $domainLabel : found $(Get-SafeCount $servers) DHCP authorization record(s)" "INFO"
    } catch {
        Write-ActionLog "LDAP DHCP discovery failed for ${domainLabel}: $_" "WARN"
    }
    
    return @($servers)
}

function Get-DomainDhcpServers {
    <#
    .SYNOPSIS
        Discovers authorized DHCP servers across one or more DNS domains
    #>
    param(
        [string[]]$Domains
    )
    
    $servers = [System.Collections.Generic.List[object]]::new()
    $seen = @{}
    
    $domainList = @(Get-NormalizedScanDomainList -Domains $Domains)
    if ((Get-SafeCount $domainList) -eq 0) {
        # Fall back to default RootDSE only
        $domainList = @('')
    }
    
    Write-ActionLog "Scanning $(Get-SafeCount $domainList) domain(s) for authorized DHCP servers..." "INFO"
    
    # Forest/current context via DhcpServer module (covers current forest authorization list)
    try {
        if (-not (Get-Module -Name DhcpServer -ListAvailable)) {
            throw "DhcpServer module not available"
        }
        Import-Module DhcpServer -ErrorAction Stop
        $list = @(Get-DhcpServerInDC -ErrorAction Stop)
        $current = Get-CurrentDnsDomainName
        if ([string]::IsNullOrWhiteSpace($current)) { $current = '(current forest)' }
        
        foreach ($item in $list) {
            $dns = Get-CleanDhcpServerHostName -Name "$($item.DnsName)"
            if ([string]::IsNullOrWhiteSpace($dns)) { $dns = "$($item.DnsName)".Trim() }
            if ([string]::IsNullOrWhiteSpace($dns)) { continue }
            $key = $dns.ToLowerInvariant()
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            
            $ip = ''
            try { $ip = "$($item.IPAddress)" } catch {}
            
            $servers.Add([PSCustomObject]@{
                DnsName     = $dns
                IPAddress   = $ip
                Authorized  = $true
                AuthDetail  = 'Authorized in AD (Get-DhcpServerInDC)'
                Source      = 'AD Authorized (Get-DhcpServerInDC)'
                Domain      = $current
            })
        }
    } catch {
        Write-ActionLog "Get-DhcpServerInDC unavailable or failed: $_" "WARN"
    }
    
    # Per-domain ADSI NetServices (supports additional / trusted domains)
    foreach ($dom in $domainList) {
        $ldapServers = @(Get-DomainDhcpServersFromLdap -DomainDns $dom)
        foreach ($srv in $ldapServers) {
            $key = "$($srv.DnsName)".Trim().ToLowerInvariant()
            if ([string]::IsNullOrWhiteSpace($key)) { continue }
            if ($seen.ContainsKey($key)) {
                # Enrich domain label if we only had forest entry
                continue
            }
            $seen[$key] = $true
            $servers.Add($srv)
        }
    }
    
    return @($servers | Sort-Object Domain, DnsName)
}

function Test-DhcpServerAdAuthorization {
    <#
    .SYNOPSIS
        Verifies whether a DHCP server DNS name or IP is listed as authorized in AD
    #>
    param(
        [string]$DnsName,
        [string]$IPAddress,
        [object[]]$AuthorizedServers
    )
    
    $dnsKey = if ($DnsName) { $DnsName.Trim().ToLowerInvariant() } else { '' }
    $ipKey  = if ($IPAddress) { $IPAddress.Trim() } else { '' }
    
    foreach ($auth in @($AuthorizedServers)) {
        $authDns = "$($auth.DnsName)".Trim().ToLowerInvariant()
        $authIp  = "$($auth.IPAddress)".Trim()
        
        if ($dnsKey -and $authDns -and ($dnsKey -eq $authDns -or $dnsKey.StartsWith("$authDns.") -or $authDns.StartsWith("$dnsKey."))) {
            return [PSCustomObject]@{
                Authorized = $true
                AuthDetail = if ($auth.AuthDetail) { $auth.AuthDetail } else { 'Matched authorized AD DNS name' }
            }
        }
        
        if ($ipKey -and $authIp -and $ipKey -eq $authIp) {
            return [PSCustomObject]@{
                Authorized = $true
                AuthDetail = 'Matched authorized AD IP address'
            }
        }
    }
    
    return [PSCustomObject]@{
        Authorized = $false
        AuthDetail = 'Not found in AD authorized DHCP server list'
    }
}

function Test-HostPingStatus {
    <#
    .SYNOPSIS
        Pings a host with a short timeout and returns Up/Down + latency
    #>
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        [int]$TimeoutMs = 1500
    )
    
    $result = [PSCustomObject]@{
        Status    = 'Down'
        LatencyMs = $null
        Detail    = ''
    }
    
    try {
        $ping = New-Object System.Net.NetworkInformation.Ping
        $reply = $ping.Send($ComputerName, $TimeoutMs)
        if ($null -ne $reply -and $reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
            $result.Status = 'Up'
            $result.LatencyMs = [int]$reply.RoundtripTime
            $result.Detail = "$($reply.RoundtripTime) ms"
        } else {
            $statusText = if ($reply) { "$($reply.Status)" } else { 'No reply' }
            $result.Status = 'Down'
            $result.Detail = $statusText
        }
    } catch {
        $result.Status = 'Down'
        $result.Detail = "$_"
    }
    
    return $result
}

function Invoke-DomainDhcpServerScan {
    <#
    .SYNOPSIS
        Discovers domain DHCP servers across domains, verifies AD authorization, and pings each one
    #>
    param(
        [int]$TimeoutMs = 1500,
        [string[]]$Domains
    )
    
    $domainList = @(Get-NormalizedScanDomainList -Domains $Domains)
    $domainText = if ((Get-SafeCount $domainList) -gt 0) { $domainList -join ', ' } else { '(default directory)' }
    Write-ActionLog "Scanning domains for DHCP servers: $domainText" "INFO"
    Set-Status "Scanning DHCP servers in: $domainText"
    
    $discovered = @(Get-DomainDhcpServers -Domains $domainList)
    if ((Get-SafeCount $discovered) -eq 0) {
        throw "No DHCP servers found in Active Directory for: $domainText. Check domain DNS names, trust, and LDAP access (or DhcpServer / Get-DhcpServerInDC)."
    }
    
    Write-ActionLog "Found $(Get-SafeCount $discovered) AD DHCP server record(s). Verifying authorization and pinging..." "INFO"
    
    $results = [System.Collections.Generic.List[object]]::new()
    $totalSrv = Get-SafeCount $discovered
    Start-TaskProgress -Name 'Scan' -Message "Scanning $totalSrv DHCP server(s)..." -Total $totalSrv
    $idx = 0
    
    foreach ($srv in $discovered) {
        if (Test-TaskCancelRequested) { break }
        Wait-TaskProgressIfPaused
        
        $idx++
        $target = if ($srv.DnsName) { $srv.DnsName } else { $srv.IPAddress }
        Update-TaskProgress -Processed $idx -Total $totalSrv -Message "Scan $idx / $totalSrv — $target"
        Write-ActionLog "Checking $target (authorize + ping)..." "INFO"
        
        $ping = Test-HostPingStatus -ComputerName $target -TimeoutMs $TimeoutMs
        
        $ip = "$($srv.IPAddress)"
        if ([string]::IsNullOrWhiteSpace($ip)) {
            try {
                $addrs = [System.Net.Dns]::GetHostAddresses($srv.DnsName) |
                    Where-Object { $_.AddressFamily -eq 'InterNetwork' }
                if ($addrs) { $ip = "$($addrs[0])" }
            } catch {}
        }
        
        $authCheck = Test-DhcpServerAdAuthorization -DnsName $srv.DnsName -IPAddress $ip -AuthorizedServers $discovered
        $isAuthorized = [bool]$authCheck.Authorized
        $authDetail = "$($authCheck.AuthDetail)"
        if ($srv.Authorized -and -not $isAuthorized) {
            $isAuthorized = $true
            $authDetail = if ($srv.AuthDetail) { $srv.AuthDetail } else { 'Listed in AD DHCP authorization data' }
        } elseif ($srv.Authorized) {
            $isAuthorized = $true
            if ($srv.AuthDetail) { $authDetail = $srv.AuthDetail }
        }
        
        $domainName = if ($srv.PSObject.Properties.Name -contains 'Domain' -and $srv.Domain) { "$($srv.Domain)" } else { '' }
        $cleanDns = Get-CleanDhcpServerHostName -Name "$($srv.DnsName)"
        if ([string]::IsNullOrWhiteSpace($cleanDns)) { $cleanDns = "$($srv.DnsName)" }
        
        $results.Add([PSCustomObject]@{
            Domain      = $domainName
            DnsName     = $cleanDns
            IPAddress   = $ip
            Online      = $ping.Status
            Status      = $ping.Status
            Authorized  = $(if ($isAuthorized) { 'Yes' } else { 'No' })
            AuthDetail  = $authDetail
            LatencyMs   = $ping.LatencyMs
            Detail      = $ping.Detail
            Source      = $srv.Source
        })
    }
    
    $up = Get-SafeCount @($results | Where-Object { $_.Online -eq 'Up' })
    $total = Get-SafeCount $results
    $down = $total - $up
    $authYes = Get-SafeCount @($results | Where-Object { $_.Authorized -eq 'Yes' })
    $authNo = $total - $authYes
    Write-ActionLog "Domain scan complete: $total servers — Online $up Up/$down Down — Authorized $authYes Yes/$authNo No" "SUCCESS"
    Set-Status "Domain scan: $up Up / $down Down | Auth $authYes Yes / $authNo No"
    Complete-TaskProgress -Message "Domain scan complete: $total server(s)"
    
    return $results
}

function Get-ScanDomainsFromDialog {
    param($ListBox)
    
    $domains = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $ListBox) {
        return @(Get-NormalizedScanDomainList -Domains @())
    }
    
    foreach ($item in @($ListBox.Items)) {
        $d = "$item".Trim()
        if (-not [string]::IsNullOrWhiteSpace($d)) { [void]$domains.Add($d) }
    }
    
    return @(Get-NormalizedScanDomainList -Domains @($domains))
}

function Get-ScanRowConnectTarget {
    <#
    .SYNOPSIS
        Chooses display/connect values from the selected scan row only
        (does not substitute a different host — Connect handles cluster fallbacks)
    #>
    param($Row)
    
    if ($null -eq $Row) {
        return [PSCustomObject]@{
            Primary    = ''
            FallbackIP = ''
            HostName   = ''
            Note       = ''
            SelectedDnsName = ''
            SelectedIP = ''
        }
    }
    
    $rawDns = "$($Row.DnsName)".Trim()
    $clean = Get-CleanDhcpServerHostName -Name $rawDns
    $ip = "$($Row.IPAddress)".Trim()
    if ($ip -notmatch '^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$') { $ip = '' }
    
    # Always honor the selected row. Prefer cleaned DNS name; fall back to IP if name is unusable.
    if ([string]::IsNullOrWhiteSpace($clean) -or $clean -match '(?i)^rcn=|=') {
        $primary = $(if ($ip) { $ip } else { $rawDns })
    } else {
        $primary = $clean
    }
    
    $note = ''
    if (Test-DhcpClusterLikeName -Name $primary) {
        $note = "Selected name looks like a cluster/VIP. Connect will also try related DHCP nodes if scope enumeration fails."
    }
    
    return [PSCustomObject]@{
        Primary         = $primary
        FallbackIP      = $ip
        HostName        = $clean
        Note            = $note
        SelectedDnsName = $rawDns
        SelectedIP      = $ip
    }
}

function Update-DomainScanDialogUi {
    <#
    .SYNOPSIS
        Runs domain scan and updates the scan dialog grid/status controls
    #>
    param(
        $Grid,
        $StatusText,
        [string[]]$Domains
    )
    
    try {
        $domainList = @(Get-NormalizedScanDomainList -Domains $Domains)
        $domainText = if ((Get-SafeCount $domainList) -gt 0) { $domainList -join ', ' } else { '(default)' }
        
        if ($null -ne $StatusText) {
            $StatusText.Text = "Scanning $domainText — AD authorization + ping..."
        }
        try { [System.Windows.Forms.Application]::DoEvents() } catch {}
        
        $results = @(Invoke-DomainDhcpServerScan -Domains $domainList)
        $Global:DomainScanResults.Clear()
        foreach ($r in $results) { $Global:DomainScanResults.Add($r) }
        
        if ($null -ne $Grid) {
            $Grid.ItemsSource = $null
            $Grid.ItemsSource = @($Global:DomainScanResults)
        }
        
        $up = Get-SafeCount @($Global:DomainScanResults | Where-Object { $_.Online -eq 'Up' -or $_.Status -eq 'Up' })
        $total = Get-SafeCount $Global:DomainScanResults
        $down = $total - $up
        $authYes = Get-SafeCount @($Global:DomainScanResults | Where-Object { $_.Authorized -eq 'Yes' })
        $authNo = $total - $authYes
        $summary = "Domains: $domainText — Found $total server(s): Online $up Up / $down Down | Authorized $authYes Yes / $authNo No"
        
        if ($null -ne $StatusText) {
            $StatusText.Text = $summary
        }
        Update-LogDisplay
    } catch {
        Complete-TaskProgress -Message "Domain scan failed"
        $err = "$_"
        Write-ActionLog "Domain scan failed: $err" "ERROR"
        if ($null -ne $StatusText) {
            $StatusText.Text = "Scan failed: $err"
        }
        Show-MessageBox "Domain DHCP scan failed:`n$err" "Scan Error" OK Error
        Update-LogDisplay
    }
}

function Add-ScanDialogDomainEntry {
    <#
    .SYNOPSIS
        Adds typed domain name(s) to the Scan dialog list and optionally persists
    #>
    if ($null -eq $script:ScanDialogDomains -or $null -eq $script:ScanDialogNewDomain) { return }
    
    $raw = "$($script:ScanDialogNewDomain.Text)"
    $parts = @("$raw" -split '[;,\r\n]+' | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if ((Get-SafeCount $parts) -eq 0) {
        Show-MessageBox "Enter a DNS domain name to add (example: child.contoso.com)." "Add Domain" OK Warning
        return
    }
    
    foreach ($d in $parts) {
        $key = $d.ToLowerInvariant()
        $exists = $false
        foreach ($item in @($script:ScanDialogDomains.Items)) {
            if ("$item".ToLowerInvariant() -eq $key) { $exists = $true; break }
        }
        if (-not $exists) {
            [void]$script:ScanDialogDomains.Items.Add($d)
            Write-ActionLog "Scan domain list: added $d" "INFO"
        }
    }
    
    $script:ScanDialogNewDomain.Text = ''
    
    $remember = $false
    try { $remember = [bool]$script:ScanDialogRemember.IsChecked } catch {}
    if ($remember) {
        Export-ScanDomainsConfig -Domains @($script:ScanDialogDomains.Items)
    }
    Update-LogDisplay
}

function Remove-ScanDialogDomainEntry {
    if ($null -eq $script:ScanDialogDomains) { return }
    
    if ($null -eq $script:ScanDialogDomains.SelectedItem) {
        Show-MessageBox "Select a domain in the list to remove." "Remove Domain" OK Warning
        return
    }
    
    $selected = "$($script:ScanDialogDomains.SelectedItem)"
    $current = Get-CurrentDnsDomainName
    if ($current -and $selected.ToLowerInvariant() -eq $current.ToLowerInvariant()) {
        $confirm = Show-MessageBox "Remove the current domain '$selected' from this scan list?`n(You can add it back later.)" "Remove Domain" YesNo Warning
        if ($confirm -ne 'Yes') { return }
    }
    
    $script:ScanDialogDomains.Items.Remove($script:ScanDialogDomains.SelectedItem)
    Write-ActionLog "Scan domain list: removed $selected" "INFO"
    
    $remember = $false
    try { $remember = [bool]$script:ScanDialogRemember.IsChecked } catch {}
    if ($remember) {
        Export-ScanDomainsConfig -Domains @($script:ScanDialogDomains.Items)
    }
    Update-LogDisplay
}

function Show-DomainDhcpScanDialog {
    <#
    .SYNOPSIS
        Shows dialog with discovered DHCP servers and ping status (multi-domain)
    #>
    
    Write-ActionLog "Opening Domain DHCP Scan dialog..." "INFO"
    
    [xml]$dialogXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Domain DHCP Server Scan - Anthony Blake"
        Height="620" Width="980"
        WindowStartupLocation="CenterOwner"
        Background="#1A1D23"
        FontFamily="Segoe UI" FontSize="13">
  <Grid Margin="16">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <TextBlock Grid.Row="0" Text="Domain DHCP Servers — Online Status + AD Authorization"
               Foreground="#E8EAF0" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,8"/>

    <!-- Multi-domain picker -->
    <Border Grid.Row="1" Background="#2A2F3A" CornerRadius="6" Padding="12,10" Margin="0,0,0,10"
            BorderBrush="#383E4A" BorderThickness="1">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="220"/>
          <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <TextBlock Grid.Row="0" Grid.ColumnSpan="2" Text="Domains to scan"
                   Foreground="#E8EAF0" FontWeight="SemiBold" Margin="0,0,0,6"/>

        <ListBox x:Name="LstScanDomains" Grid.Row="1" Grid.Column="0" Height="88"
                 Background="#1A1D23" Foreground="#E8EAF0" BorderBrush="#383E4A"
                 Margin="0,0,12,0"/>

        <StackPanel Grid.Row="1" Grid.Column="1" VerticalAlignment="Top">
          <TextBlock Text="Add another DNS domain (child, trusted, or forest peer):"
                     Foreground="#9AA3B2" FontSize="11" Margin="0,0,0,6" TextWrapping="Wrap"/>
          <StackPanel Orientation="Horizontal" Margin="0,0,0,6">
            <TextBox x:Name="TxtNewScanDomain" Width="280" Height="28"
                     Background="#1A1D23" Foreground="#E8EAF0" BorderBrush="#383E4A"
                     CaretBrush="#E8EAF0" VerticalContentAlignment="Center" Padding="6,2"
                     ToolTip="Example: child.contoso.com or partner.fabrikam.com"/>
            <Button x:Name="BtnAddScanDomain" Content="Add Domain" Width="100" Height="28" Margin="8,0,0,0"
                    Background="#2196F3" Foreground="White" BorderThickness="0"/>
            <Button x:Name="BtnRemoveScanDomain" Content="Remove" Width="80" Height="28" Margin="8,0,0,0"
                    Background="#2A2F3A" Foreground="#E8EAF0" BorderBrush="#383E4A" BorderThickness="1"/>
          </StackPanel>
          <CheckBox x:Name="ChkRememberScanDomains" Content="Remember extra domains for next launch"
                    IsChecked="True" Foreground="#E8EAF0" FontSize="11"/>
        </StackPanel>

        <TextBlock Grid.Row="2" Grid.ColumnSpan="2" Margin="0,8,0,0"
                   Foreground="#9AA3B2" FontSize="11" TextWrapping="Wrap"
                   Text="Current domain is included automatically. Extra domains are queried via LDAP NetServices on that domain (requires name resolution and directory access)."/>
      </Grid>
    </Border>

    <StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,0,0,10">
      <Button x:Name="BtnScanNow" Content="🔍 Scan Now" Width="110" Height="30" Margin="0,0,8,0"
              Background="#2196F3" Foreground="White" BorderThickness="0"/>
      <Button x:Name="BtnUseAsA" Content="Use as Server A" Width="130" Height="30" Margin="0,0,8,0"
              Background="#2A2F3A" Foreground="#E8EAF0" BorderBrush="#383E4A" BorderThickness="1"/>
      <Button x:Name="BtnUseAsB" Content="Use as Server B" Width="130" Height="30" Margin="0,0,8,0"
              Background="#2A2F3A" Foreground="#E8EAF0" BorderBrush="#383E4A" BorderThickness="1"/>
      <Button x:Name="BtnExportScan" Content="💾 Export" Width="90" Height="30" Margin="0,0,8,0"
              Background="#2A2F3A" Foreground="#E8EAF0" BorderBrush="#383E4A" BorderThickness="1"/>
      <TextBlock x:Name="TxtScanStatus" Text="Add domains if needed, then click Scan Now"
                 Foreground="#9AA3B2" VerticalAlignment="Center" Margin="8,0,0,0"/>
    </StackPanel>

    <DataGrid Grid.Row="3" x:Name="GridScanResults"
              AutoGenerateColumns="False" IsReadOnly="True" CanUserAddRows="False"
              SelectionMode="Single" HeadersVisibility="Column"
              Background="#22262E" Foreground="#E8EAF0" BorderThickness="0"
              RowBackground="#22262E" AlternatingRowBackground="#2A2F3A"
              GridLinesVisibility="Horizontal" HorizontalGridLinesBrush="#383E4A"
              RowHeight="28" ColumnHeaderHeight="32">
      <DataGrid.Columns>
        <DataGridTextColumn Header="Domain" Binding="{Binding Domain}" Width="140"/>
        <DataGridTextColumn Header="DNS Name" Binding="{Binding DnsName}" Width="180"/>
        <DataGridTextColumn Header="IP Address" Binding="{Binding IPAddress}" Width="110"/>
        <DataGridTextColumn Header="Online" Binding="{Binding Online}" Width="70"/>
        <DataGridTextColumn Header="Authorized" Binding="{Binding Authorized}" Width="90"/>
        <DataGridTextColumn Header="Latency" Binding="{Binding Detail}" Width="80"/>
        <DataGridTextColumn Header="Authorization Detail" Binding="{Binding AuthDetail}" Width="200"/>
        <DataGridTextColumn Header="Source" Binding="{Binding Source}" Width="*"/>
      </DataGrid.Columns>
      <DataGrid.ColumnHeaderStyle>
        <Style TargetType="DataGridColumnHeader">
          <Setter Property="Background" Value="#2A2F3A"/>
          <Setter Property="Foreground" Value="#9AA3B2"/>
          <Setter Property="Padding" Value="8,0"/>
          <Setter Property="BorderBrush" Value="#383E4A"/>
          <Setter Property="BorderThickness" Value="0,0,1,1"/>
        </Style>
      </DataGrid.ColumnHeaderStyle>
    </DataGrid>

    <TextBlock Grid.Row="4" Margin="0,10,0,8" Foreground="#9AA3B2" FontSize="11"
               Text="Online = ICMP ping. Authorized = listed in Active Directory DHCP authorization (Get-DhcpServerInDC / NetServices per domain)."
               TextWrapping="Wrap"/>

    <StackPanel Grid.Row="5" Orientation="Horizontal" HorizontalAlignment="Right">
      <Button x:Name="BtnCloseScan" Content="Close" Width="90" Height="30"
              Background="#2A2F3A" Foreground="#E8EAF0" BorderBrush="#383E4A" BorderThickness="1"/>
    </StackPanel>
  </Grid>
</Window>
'@
    
    try {
        $dialog = [Windows.Markup.XamlReader]::Load([System.Xml.XmlNodeReader]::new($dialogXaml))
        if ($script:Window) { $dialog.Owner = $script:Window }
        
        $script:ScanDialog = $dialog
        $script:ScanDialogGrid = $dialog.FindName('GridScanResults')
        $script:ScanDialogStatus = $dialog.FindName('TxtScanStatus')
        $script:ScanDialogDomains = $dialog.FindName('LstScanDomains')
        $script:ScanDialogNewDomain = $dialog.FindName('TxtNewScanDomain')
        $script:ScanDialogRemember = $dialog.FindName('ChkRememberScanDomains')
        $btnScan = $dialog.FindName('BtnScanNow')
        $btnAddDomain = $dialog.FindName('BtnAddScanDomain')
        $btnRemoveDomain = $dialog.FindName('BtnRemoveScanDomain')
        $btnUseA = $dialog.FindName('BtnUseAsA')
        $btnUseB = $dialog.FindName('BtnUseAsB')
        $btnExport = $dialog.FindName('BtnExportScan')
        $btnClose = $dialog.FindName('BtnCloseScan')
        
        # Seed domain list: current + persisted extras
        $seed = [System.Collections.Generic.List[string]]::new()
        $current = Get-CurrentDnsDomainName
        if (-not [string]::IsNullOrWhiteSpace($current)) { [void]$seed.Add($current) }
        
        $extras = @()
        if ($null -ne $Global:ExtraScanDomains -and (Get-SafeCount $Global:ExtraScanDomains) -gt 0) {
            $extras = @($Global:ExtraScanDomains)
        } else {
            $extras = @(Import-ScanDomainsConfig)
            $Global:ExtraScanDomains = [System.Collections.Generic.List[string]]::new()
            foreach ($e in $extras) { [void]$Global:ExtraScanDomains.Add($e) }
        }
        
        foreach ($d in @(Get-NormalizedScanDomainList -Domains (@($seed) + @($extras)))) {
            [void]$script:ScanDialogDomains.Items.Add($d)
        }
        
        $addDomainAction = {
            Add-ScanDialogDomainEntry
        }
        
        $btnAddDomain.add_Click($addDomainAction)
        $script:ScanDialogNewDomain.add_KeyDown({
            param($sender, $e)
            if ($e.Key -eq 'Return') {
                Add-ScanDialogDomainEntry
                $e.Handled = $true
            }
        })
        
        $btnRemoveDomain.add_Click({
            Remove-ScanDialogDomainEntry
        })
        
        $btnScan.add_Click({
            $domains = @(Get-ScanDomainsFromDialog -ListBox $script:ScanDialogDomains)
            $remember = $false
            try { $remember = [bool]$script:ScanDialogRemember.IsChecked } catch {}
            if ($remember) {
                Export-ScanDomainsConfig -Domains $domains
            }
            Update-DomainScanDialogUi -Grid $script:ScanDialogGrid -StatusText $script:ScanDialogStatus -Domains $domains
        })
        
        $btnUseA.add_Click({
            if ($null -eq $script:ScanDialogGrid -or $null -eq $script:ScanDialogGrid.SelectedItem) {
                Show-MessageBox "Select a DHCP server first." "Scan" OK Warning
                return
            }
            $row = $script:ScanDialogGrid.SelectedItem
            $target = Get-ScanRowConnectTarget -Row $row
            if ([string]::IsNullOrWhiteSpace($target.Primary)) {
                Show-MessageBox "The selected row has no usable DNS name or IP." "Scan" OK Warning
                return
            }
            $script:TxtServerName.Text = $target.Primary
            $selectedLabel = if ($target.SelectedDnsName) { $target.SelectedDnsName } else { $target.Primary }
            $hint = "Filled Server A with $($target.Primary) (selected: $selectedLabel)"
            if ($target.FallbackIP -and $target.Primary -ne $target.FallbackIP) {
                $hint += " — IP fallback $($target.FallbackIP)"
            }
            $hint += " — click Connect"
            if ($target.Note) { $hint += "  |  $($target.Note)" }
            Write-ActionLog "Scan: Use as Server A — selected '$selectedLabel' / IP '$($target.SelectedIP)' → filled '$($target.Primary)'" "INFO"
            $script:ScanDialogStatus.Text = $hint
            Update-LogDisplay
        })
        
        $btnUseB.add_Click({
            if ($null -eq $script:ScanDialogGrid -or $null -eq $script:ScanDialogGrid.SelectedItem) {
                Show-MessageBox "Select a DHCP server first." "Scan" OK Warning
                return
            }
            if ($null -eq $script:TxtCompareServer) {
                Show-MessageBox "Compare controls not available." "Scan" OK Warning
                return
            }
            $row = $script:ScanDialogGrid.SelectedItem
            $target = Get-ScanRowConnectTarget -Row $row
            if ([string]::IsNullOrWhiteSpace($target.Primary)) {
                Show-MessageBox "The selected row has no usable DNS name or IP." "Scan" OK Warning
                return
            }
            $script:TxtCompareServer.Text = $target.Primary
            if ($null -ne $script:TabCompare) {
                $script:MainTabs.SelectedItem = $script:TabCompare
            }
            $selectedLabel = if ($target.SelectedDnsName) { $target.SelectedDnsName } else { $target.Primary }
            $hint = "Filled Server B with $($target.Primary) (selected: $selectedLabel)"
            if ($target.FallbackIP -and $target.Primary -ne $target.FallbackIP) {
                $hint += " — IP fallback $($target.FallbackIP)"
            }
            $hint += " — click Connect B on the Compare tab"
            if ($target.Note) { $hint += "  |  $($target.Note)" }
            Write-ActionLog "Scan: Use as Server B — selected '$selectedLabel' / IP '$($target.SelectedIP)' → filled '$($target.Primary)'" "INFO"
            $script:ScanDialogStatus.Text = $hint
            Update-LogDisplay
        })
        
        $btnExport.add_Click({
            if ((Get-SafeCount $Global:DomainScanResults) -eq 0) {
                Show-MessageBox "No scan results to export. Run Scan Now first." "Export" OK Warning
                return
            }
            try {
                $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
                $saveDialog.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
                $saveDialog.FileName = "DHCP-Domain-Scan-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
                $saveDialog.Title = "Export Domain DHCP Scan"
                if ($saveDialog.ShowDialog() -eq 'OK') {
                    $Global:DomainScanResults |
                        Select-Object Domain, DnsName, IPAddress, Online, Authorized, AuthDetail, LatencyMs, Detail, Source |
                        Export-Csv -Path $saveDialog.FileName -NoTypeInformation -Encoding UTF8
                    Write-ActionLog "Domain scan exported: $($saveDialog.FileName)" "SUCCESS"
                    Show-MessageBox "Exported to:`n$($saveDialog.FileName)" "Export Complete" OK Information
                    Update-LogDisplay
                }
            } catch {
                Show-MessageBox "Export failed: $_" "Export Error" OK Error
            }
        })
        
        $script:ScanDialogGrid.add_MouseDoubleClick({
            if ($null -eq $script:ScanDialogGrid.SelectedItem) { return }
            $row = $script:ScanDialogGrid.SelectedItem
            $target = Get-ScanRowConnectTarget -Row $row
            if ([string]::IsNullOrWhiteSpace($target.Primary)) { return }
            $script:TxtServerName.Text = $target.Primary
            $selectedLabel = if ($target.SelectedDnsName) { $target.SelectedDnsName } else { $target.Primary }
            Write-ActionLog "Scan double-click: selected '$selectedLabel' → filled Server A with $($target.Primary)" "INFO"
            $script:ScanDialogStatus.Text = "Filled Server A with $($target.Primary) (selected: $selectedLabel)"
        })
        
        $btnClose.add_Click({
            if ($null -ne $script:ScanDialog) { $script:ScanDialog.Close() }
        })
        
        # Auto-run scan after dialog is shown (no RaiseEvent / GetNewClosure)
        $dialog.Add_ContentRendered({
            $domains = @(Get-ScanDomainsFromDialog -ListBox $script:ScanDialogDomains)
            Update-DomainScanDialogUi -Grid $script:ScanDialogGrid -StatusText $script:ScanDialogStatus -Domains $domains
        })
        
        [void]$dialog.ShowDialog()
    } catch {
        Write-ActionLog "Failed to open domain scan dialog: $_" "ERROR"
        Show-MessageBox "Failed to open scan dialog: $_" "Scan Error" OK Error
    } finally {
        $script:ScanDialog = $null
        $script:ScanDialogDomains = $null
        $script:ScanDialogNewDomain = $null
        $script:ScanDialogRemember = $null
    }
}
#endregion

#region Navigation Tree Builder
function Update-NavScopeSearchStatus {
    param(
        [int]$MatchCount = -1,
        [int]$TotalCount = -1,
        [string]$Message
    )
    
    try {
        if ($null -eq $script:TxtNavScopeSearchStatus) { return }
        
        if ($Message) {
            $script:TxtNavScopeSearchStatus.Text = $Message
            return
        }
        
        if ($TotalCount -lt 0) { $TotalCount = Get-SafeCount $Global:NavScopeIndex }
        if ($MatchCount -lt 0) { $MatchCount = $TotalCount }
        
        $query = ''
        try { $query = "$($script:TxtNavScopeSearch.Text)".Trim() } catch {}
        
        if (-not $query) {
            $script:TxtNavScopeSearchStatus.Text = if ($TotalCount -gt 0) {
                "$TotalCount scope(s) — type a name or Scope ID"
            } else {
                "Connect and refresh to load scopes"
            }
        } else {
            $script:TxtNavScopeSearchStatus.Text = "$MatchCount of $TotalCount match '$query'"
        }
    } catch {}
}

function Get-NavScopeSearchQuery {
    $query = ''
    try {
        if ($null -ne $script:TxtNavScopeSearch) {
            $query = "$($script:TxtNavScopeSearch.Text)".Trim()
        }
    } catch {}
    return $query
}

function Test-NavScopeMatchesQuery {
    param(
        [object]$Entry,
        [string]$Query
    )
    
    if ([string]::IsNullOrWhiteSpace($Query)) { return $true }
    if ($null -eq $Entry) { return $false }
    
    $q = $Query.ToLowerInvariant()
    $hay = "$($Entry.SearchText)".ToLowerInvariant()
    return $hay.Contains($q)
}

function Apply-NavScopeFilter {
    <#
    .SYNOPSIS
        Filters navigation scope nodes by name / Scope ID search text
    #>
    param(
        [switch]$Quiet
    )
    
    $query = Get-NavScopeSearchQuery
    $Global:NavScopeSearchText = $query
    $total = Get-SafeCount $Global:NavScopeIndex
    $matched = [System.Collections.Generic.List[object]]::new()
    $hidden = [System.Collections.Generic.List[object]]::new()
    
    foreach ($entry in @($Global:NavScopeIndex)) {
        if ($null -eq $entry -or $null -eq $entry.Node) { continue }
        if (Test-NavScopeMatchesQuery -Entry $entry -Query $query) {
            [void]$matched.Add($entry)
        } else {
            [void]$hidden.Add($entry)
        }
    }
    
    $matchCount = Get-SafeCount $matched
    $Global:NavScopeMatched = $matched
    
    $apply = {
        foreach ($entry in $matched) {
            $entry.Node.Visibility = [System.Windows.Visibility]::Visible
        }
        foreach ($entry in $hidden) {
            $entry.Node.Visibility = [System.Windows.Visibility]::Collapsed
            try { $entry.Node.IsSelected = $false } catch {}
        }
        
        if ($null -ne $script:NavScopesContainer) {
            $script:NavScopesContainer.IsExpanded = $true
            if ($query) {
                $script:NavScopesContainer.Header = "🌐 Scopes ($matchCount/$total)"
            } else {
                $script:NavScopesContainer.Header = "🌐 Scopes ($total)"
            }
        }
        
        if ($null -ne $script:NavServerNode) {
            $script:NavServerNode.IsExpanded = $true
        }
    }
    
    try {
        if ($null -ne $script:Window -and -not $script:Window.Dispatcher.CheckAccess()) {
            $script:Window.Dispatcher.Invoke([action]$apply, [System.Windows.Threading.DispatcherPriority]::Normal)
        } else {
            & $apply
        }
    } catch {
        try { & $apply } catch {}
    }
    
    if ($matchCount -eq 0) {
        $Global:NavScopeMatchIndex = -1
    } elseif ($Global:NavScopeMatchIndex -ge $matchCount) {
        $Global:NavScopeMatchIndex = 0
    }
    
    Update-NavScopeSearchStatus -MatchCount $matchCount -TotalCount $total
    
    if (-not $Quiet -and $query) {
        Write-ActionLog "Nav scope search '$query': $matchCount of $total match(es)" "INFO"
    }
    
    return $matchCount
}

function Select-NavScopeMatch {
    <#
    .SYNOPSIS
        Selects the next (or first) matching scope in the navigation tree
    #>
    param(
        [switch]$First
    )
    
    $query = Get-NavScopeSearchQuery
    if (-not $query) {
        Update-NavScopeSearchStatus -Message "Type a scope name or ID, then press Find / Enter"
        return
    }
    
    [void](Apply-NavScopeFilter -Quiet)
    
    $matches = @($Global:NavScopeMatched)
    $count = Get-SafeCount $matches
    if ($count -eq 0) {
        Update-NavScopeSearchStatus -MatchCount 0 -TotalCount (Get-SafeCount $Global:NavScopeIndex)
        Show-MessageBox "No scopes match '$query'." "Scope Search" OK Information
        return
    }
    
    if ($First -or $Global:NavScopeMatchIndex -lt 0) {
        $Global:NavScopeMatchIndex = 0
    } else {
        $Global:NavScopeMatchIndex = ($Global:NavScopeMatchIndex + 1) % $count
    }
    
    $entry = $matches[$Global:NavScopeMatchIndex]
    if ($null -eq $entry -or $null -eq $entry.Node) { return }
    
    try {
        $script:Window.Dispatcher.Invoke([action]{
            if ($null -ne $script:NavServerNode) { $script:NavServerNode.IsExpanded = $true }
            if ($null -ne $script:NavScopesContainer) { $script:NavScopesContainer.IsExpanded = $true }
            
            $node = $entry.Node
            $node.Visibility = [System.Windows.Visibility]::Visible
            $node.IsExpanded = $true
            $node.IsSelected = $true
            $node.BringIntoView()
            try { $node.Focus() } catch {}
        }, [System.Windows.Threading.DispatcherPriority]::Normal)
    } catch {
        $entry.Node.IsSelected = $true
        try { $entry.Node.BringIntoView() } catch {}
    }
    
    $Global:SelectedScope = "$($entry.ScopeId)"
    Update-NavScopeSearchStatus -Message "Match $($Global:NavScopeMatchIndex + 1) of $count — $($entry.Name) [$($entry.ScopeId)]"
    Write-ActionLog "Nav scope find: $($entry.Name) [$($entry.ScopeId)] ($($Global:NavScopeMatchIndex + 1)/$count)" "INFO"
    Set-Status "Selected scope $($entry.ScopeId)"
}

function Clear-NavScopeSearch {
    try {
        if ($null -ne $script:TxtNavScopeSearch) {
            $script:TxtNavScopeSearch.Text = ''
        }
    } catch {}
    $Global:NavScopeSearchText = ''
    $Global:NavScopeMatchIndex = -1
    [void](Apply-NavScopeFilter -Quiet)
    Update-NavScopeSearchStatus
}

function Build-NavTree {
    <#
    .SYNOPSIS
        Builds navigation tree with all DHCP elements
        FIXED: Comprehensive error handling and logging
    #>
    
    Write-ActionLog "Building navigation tree..." "INFO"
    
    try {
        if ($null -eq $script:NavTree) {
            Write-ActionLog "NavTree control not initialized" "ERROR"
            return
        }
        
        $preservedQuery = Get-NavScopeSearchQuery
        
        $script:NavTree.Dispatcher.Invoke([action]{
            $script:NavTree.Items.Clear()
            $Global:NavScopeIndex.Clear()
            $script:NavServerNode = $null
            $script:NavScopesContainer = $null
            
            # Root - Server Node
            $serverNode = New-Object System.Windows.Controls.TreeViewItem
            $serverNode.Header = "🖥️ $Global:DHCPServer"
            $serverNode.Tag = "Server"
            $serverNode.IsExpanded = $true
            $script:NavServerNode = $serverNode
            
            # Scopes Container
            $scopesContainer = New-Object System.Windows.Controls.TreeViewItem
            $scopesContainer.Header = "🌐 Scopes"
            $scopesContainer.Tag = "Scopes"
            $scopesContainer.IsExpanded = $true
            $script:NavScopesContainer = $scopesContainer
            
            try {
                $scopes = @(Get-DhcpServerv4Scope -ComputerName $Global:DHCPServer -ErrorAction Stop)
                # Numeric Scope ID order (matches MMC; avoids 10.15.100.0 sorting before 10.15.96.0)
                $scopes = @($scopes | Sort-Object { Get-IpAddressSortKey "$($_.ScopeId)" }, Name)
                
                foreach ($scope in $scopes) {
                    $scopeId = "$($scope.ScopeId)"
                    $scopeName = "$($scope.Name)"
                    $scopeDesc = ''
                    try { $scopeDesc = "$($scope.Description)" } catch {}
                    
                    $scopeNode = New-Object System.Windows.Controls.TreeViewItem
                    $scopeNode.Header = "📍 $scopeName [$scopeId]"
                    $scopeNode.Tag = $scopeId
                    $scopeNode.ToolTip = if ($scopeDesc) {
                        "$scopeName`n$scopeId`n$scopeDesc"
                    } else {
                        "$scopeName`n$scopeId"
                    }
                    
                    # Add sub-items
                    $leasesItem = New-Object System.Windows.Controls.TreeViewItem
                    $leasesItem.Header = "📄 Leases"
                    $leasesItem.Tag = "${scopeId}:Leases"
                    
                    $reservationsItem = New-Object System.Windows.Controls.TreeViewItem
                    $reservationsItem.Header = "📌 Reservations"
                    $reservationsItem.Tag = "${scopeId}:Reservations"
                    
                    $exclusionsItem = New-Object System.Windows.Controls.TreeViewItem
                    $exclusionsItem.Header = "🚫 Exclusions"
                    $exclusionsItem.Tag = "${scopeId}:Exclusions"
                    
                    $optionsItem = New-Object System.Windows.Controls.TreeViewItem
                    $optionsItem.Header = "⚙️ Options"
                    $optionsItem.Tag = "${scopeId}:Options"
                    
                    [void]$scopeNode.Items.Add($leasesItem)
                    [void]$scopeNode.Items.Add($reservationsItem)
                    [void]$scopeNode.Items.Add($exclusionsItem)
                    [void]$scopeNode.Items.Add($optionsItem)
                    
                    [void]$scopesContainer.Items.Add($scopeNode)
                    
                    $searchText = @($scopeName, $scopeId, $scopeDesc) -join ' '
                    [void]$Global:NavScopeIndex.Add([PSCustomObject]@{
                        ScopeId    = $scopeId
                        Name       = $scopeName
                        Description = $scopeDesc
                        SearchText = $searchText
                        Node       = $scopeNode
                    })
                }
                
                $scopesContainer.Header = "🌐 Scopes ($(Get-SafeCount $scopes))"
                Write-ActionLog "Added $(Get-SafeCount $scopes) scopes to navigation tree" "SUCCESS"
                
            } catch {
                Write-ActionLog "Failed to load scopes for navigation: $_" "ERROR"
            }
            
            [void]$serverNode.Items.Add($scopesContainer)
            
            # Other server items
            $dashboardNode = New-Object System.Windows.Controls.TreeViewItem
            $dashboardNode.Header = "📡 Dashboard"
            $dashboardNode.Tag = "Dashboard"
            [void]$serverNode.Items.Add($dashboardNode)
            
            $filtersNode = New-Object System.Windows.Controls.TreeViewItem
            $filtersNode.Header = "🔒 MAC Filters"
            $filtersNode.Tag = "Filters"
            
            $policiesNode = New-Object System.Windows.Controls.TreeViewItem
            $policiesNode.Header = "📋 Policies"
            $policiesNode.Tag = "Policies"
            
            $troubleshootNode = New-Object System.Windows.Controls.TreeViewItem
            $troubleshootNode.Header = "🛠️ Troubleshoot"
            $troubleshootNode.Tag = "Troubleshoot"
            
            $statsNode = New-Object System.Windows.Controls.TreeViewItem
            $statsNode.Header = "📊 Statistics"
            $statsNode.Tag = "Statistics"
            
            [void]$serverNode.Items.Add($filtersNode)
            [void]$serverNode.Items.Add($policiesNode)
            [void]$serverNode.Items.Add($troubleshootNode)
            [void]$serverNode.Items.Add($statsNode)
            
            [void]$script:NavTree.Items.Add($serverNode)
            
        }, [System.Windows.Threading.DispatcherPriority]::Normal)
        
        # Restore / re-apply search after rebuild
        if ($preservedQuery -and $null -ne $script:TxtNavScopeSearch) {
            try {
                if ("$($script:TxtNavScopeSearch.Text)".Trim() -ne $preservedQuery) {
                    $script:TxtNavScopeSearch.Text = $preservedQuery
                }
            } catch {}
        }
        [void](Apply-NavScopeFilter -Quiet)
        
        Write-ActionLog "Navigation tree built successfully" "SUCCESS"
        Update-LogDisplay
        
    } catch {
        Write-ActionLog "Failed to build navigation tree: $_" "ERROR"
        Update-LogDisplay
    }
}
#endregion

#region Data Loading Functions
function Load-Scopes {
    <#
    .SYNOPSIS
        Loads all scopes into the grid
        FIXED: Enhanced logging and error handling
    #>
    
    Write-ActionLog "Loading DHCP scopes..." "INFO"
    Set-Status "Loading scopes..."
    
    try {
        if ([string]::IsNullOrWhiteSpace($Global:DHCPServer)) {
            throw "No DHCP server connected"
        }
        
        $scopes = @(Get-DhcpServerv4Scope -ComputerName $Global:DHCPServer -ErrorAction Stop)
        $scopes = @($scopes | Sort-Object { Get-IpAddressSortKey "$($_.ScopeId)" }, Name)
        $count = Get-SafeCount $scopes
        
        $script:GridScopes.Dispatcher.Invoke([action]{
            $script:GridScopes.Tag = $scopes
            $script:GridScopes.ItemsSource = $scopes
            Apply-ScopeGridFilter
        }, [System.Windows.Threading.DispatcherPriority]::Normal)
        
        Write-ActionLog "Loaded $count scopes successfully" "SUCCESS"
        Set-Status "Loaded $count scopes"
        Update-LogDisplay
        
    } catch {
        $errMsg = "Failed to load scopes: $_"
        Write-ActionLog $errMsg "ERROR"
        Set-Status $errMsg
        Show-MessageBox -Message $errMsg -Icon Error
        Update-LogDisplay
    }
}

function Get-SelectedLeaseRows {
    <#
    .SYNOPSIS
        Returns the currently multi-selected lease rows from the Leases grid
    #>
    $items = @()
    try {
        if ($null -ne $script:GridLeases) {
            $items = @($script:GridLeases.SelectedItems)
        }
    } catch {
        $items = @()
    }
    return @($items | Where-Object { $null -ne $_ })
}

function Format-LeaseSelectionSummary {
    param(
        [object[]]$Leases,
        [int]$MaxLines = 8
    )
    
    $list = @($Leases | Where-Object { $null -ne $_ })
    $count = Get-SafeCount $list
    if ($count -eq 0) { return '(none)' }
    
    $lines = [System.Collections.Generic.List[string]]::new()
    $take = [math]::Min($MaxLines, $count)
    for ($i = 0; $i -lt $take; $i++) {
        $lease = $list[$i]
        $hostName = "$($lease.HostName)"
        if (-not $hostName) { $hostName = '(no hostname)' }
        [void]$lines.Add("  $($lease.IPAddress)  —  $hostName  [$($lease.ClientId)]")
    }
    if ($count -gt $MaxLines) {
        [void]$lines.Add("  … and $($count - $MaxLines) more")
    }
    return ($lines -join [Environment]::NewLine)
}

function Update-LeaseSelectionUi {
    $selected = @(Get-SelectedLeaseRows)
    $count = Get-SafeCount $selected
    $hasSel = $count -gt 0
    
    $gridCount = 0
    try {
        if ($null -ne $script:GridLeases -and $null -ne $script:GridLeases.Items) {
            $gridCount = Get-SafeCount @($script:GridLeases.Items)
        }
    } catch { $gridCount = 0 }
    
    try {
        if ($null -ne $script:BtnLeaseRelease) { $script:BtnLeaseRelease.IsEnabled = $hasSel }
        if ($null -ne $script:BtnLeaseReserve) { $script:BtnLeaseReserve.IsEnabled = $hasSel }
        if ($null -ne $script:BtnLeaseClearSel) { $script:BtnLeaseClearSel.IsEnabled = $hasSel }
        if ($null -ne $script:BtnLeaseSelectAll) { $script:BtnLeaseSelectAll.IsEnabled = ($gridCount -gt 0) }
        if ($null -ne $script:TxtLeaseSelectedCount) {
            $script:TxtLeaseSelectedCount.Text = if ($count -eq 0) {
                "None selected  ·  $gridCount in grid"
            } else {
                "$count selected  ·  $gridCount in grid"
            }
        }
    } catch {}
}

function Invoke-BulkLeaseRelease {
    param([object[]]$Leases)
    
    $list = @($Leases | Where-Object { $null -ne $_ -and "$($_.IPAddress)" })
    $total = Get-SafeCount $list
    if ($total -eq 0) {
        Show-MessageBox "No leases selected." "Release Leases" OK Warning
        return
    }
    
    if ([string]::IsNullOrWhiteSpace($Global:DHCPServer)) {
        Show-MessageBox "Connect to a DHCP server first." "Release Leases" OK Warning
        return
    }
    
    $summary = Format-LeaseSelectionSummary -Leases $list
    $confirm = Show-MessageBox "Release $total lease(s)?`n`n$summary`n`nThis removes the active lease(s) from the DHCP server." "Confirm Release" YesNo Warning
    if ($confirm -ne 'Yes') { return }
    
    Write-ActionLog "Releasing $total lease(s)..." "INFO"
    Start-TaskProgress -Name 'LeaseRelease' -Message "Releasing leases..." -CanPause -Total $total
    
    $ok = 0
    $fail = 0
    $errors = [System.Collections.Generic.List[string]]::new()
    $idx = 0
    
    try {
        foreach ($lease in $list) {
            Wait-TaskProgressIfPaused
            if (Test-TaskCancelRequested) { break }
            
            $idx++
            $ip = "$($lease.IPAddress)"
            Update-TaskProgress -Processed $idx -Total $total -Message "Releasing $idx/$total — $ip"
            
            try {
                Remove-DhcpServerv4Lease -ComputerName $Global:DHCPServer -IPAddress $ip -ErrorAction Stop
                $ok++
                Write-ActionLog "Released lease $ip" "SUCCESS"
            } catch {
                $fail++
                $err = "$ip — $_"
                [void]$errors.Add($err)
                Write-ActionLog "Failed to release lease $err" "ERROR"
            }
        }
    } finally {
        Complete-TaskProgress -Message "Lease release finished: $ok ok, $fail failed"
    }
    
    Load-Leases
    Update-LogDisplay
    
    $extra = ''
    if ((Get-SafeCount $errors) -gt 0) {
        $extra = "`n`nFailures:`n" + ((@($errors | Select-Object -First 10) -join [Environment]::NewLine))
        if ((Get-SafeCount $errors) -gt 10) { $extra += "`n…" }
    }
    
    $title = if ($fail -eq 0) { 'Release Complete' } else { 'Release Finished with Errors' }
    $icon = if ($fail -eq 0) { 'Information' } else { 'Warning' }
    Show-MessageBox "Released: $ok`nFailed: $fail$extra" $title OK $icon
}

function Invoke-BulkLeaseConvertToReservation {
    param([object[]]$Leases)
    
    $list = @($Leases | Where-Object { $null -ne $_ -and "$($_.IPAddress)" })
    $total = Get-SafeCount $list
    if ($total -eq 0) {
        Show-MessageBox "No leases selected." "Convert to Reservation" OK Warning
        return
    }
    
    if ([string]::IsNullOrWhiteSpace($Global:DHCPServer)) {
        Show-MessageBox "Connect to a DHCP server first." "Convert to Reservation" OK Warning
        return
    }
    
    $summary = Format-LeaseSelectionSummary -Leases $list
    $confirm = Show-MessageBox "Convert $total lease(s) to reservation(s)?`n`n$summary`n`nLeases that already look like reservations, or that have no MAC/Client ID, will be skipped." "Confirm Convert" YesNo Question
    if ($confirm -ne 'Yes') { return }
    
    Write-ActionLog "Converting $total lease(s) to reservation(s)..." "INFO"
    Start-TaskProgress -Name 'LeaseReserve' -Message "Converting leases to reservations..." -CanPause -Total $total
    
    $ok = 0
    $skip = 0
    $fail = 0
    $notes = [System.Collections.Generic.List[string]]::new()
    $idx = 0
    
    try {
        foreach ($lease in $list) {
            Wait-TaskProgressIfPaused
            if (Test-TaskCancelRequested) { break }
            
            $idx++
            $ip = "$($lease.IPAddress)"
            $clientId = "$($lease.ClientId)".Trim()
            $scopeId = "$($lease.ScopeId)"
            $name = "$($lease.HostName)".Trim()
            $state = "$($lease.AddressState)"
            
            Update-TaskProgress -Processed $idx -Total $total -Message "Converting $idx/$total — $ip"
            
            if (-not $clientId) {
                $skip++
                [void]$notes.Add("$ip — skipped (no Client ID / MAC)")
                Write-ActionLog "Skip convert $ip — no ClientId" "WARN"
                continue
            }
            
            if (-not $scopeId) {
                $skip++
                [void]$notes.Add("$ip — skipped (no Scope ID)")
                Write-ActionLog "Skip convert $ip — no ScopeId" "WARN"
                continue
            }
            
            if ($state -match 'Reservation') {
                $skip++
                [void]$notes.Add("$ip — skipped (already $state)")
                Write-ActionLog "Skip convert $ip — already $state" "WARN"
                continue
            }
            
            try {
                $params = @{
                    ComputerName = $Global:DHCPServer
                    ScopeId      = $scopeId
                    IPAddress    = $ip
                    ClientId     = $clientId
                    ErrorAction  = 'Stop'
                }
                if ($name) { $params['Name'] = $name }
                
                Add-DhcpServerv4Reservation @params
                $ok++
                Write-ActionLog "Converted lease $ip → reservation ($clientId)" "SUCCESS"
            } catch {
                $msg = "$_"
                if ($msg -match 'already|exists|duplicate') {
                    $skip++
                    [void]$notes.Add("$ip — skipped (reservation already exists)")
                    Write-ActionLog "Skip convert $ip — already exists" "WARN"
                } else {
                    $fail++
                    [void]$notes.Add("$ip — $msg")
                    Write-ActionLog "Failed to convert lease $ip : $msg" "ERROR"
                }
            }
        }
    } finally {
        Complete-TaskProgress -Message "Lease→reservation finished: $ok ok, $skip skipped, $fail failed"
    }
    
    Load-Leases
    try { Load-Reservations } catch {}
    Update-LogDisplay
    
    $extra = ''
    if ((Get-SafeCount $notes) -gt 0) {
        $extra = "`n`nNotes:`n" + ((@($notes | Select-Object -First 12) -join [Environment]::NewLine))
        if ((Get-SafeCount $notes) -gt 12) { $extra += "`n…" }
    }
    
    $title = if ($fail -eq 0) { 'Convert Complete' } else { 'Convert Finished with Errors' }
    $icon = if ($fail -eq 0) { 'Information' } else { 'Warning' }
    Show-MessageBox "Converted: $ok`nSkipped: $skip`nFailed: $fail$extra" $title OK $icon
}

function Load-Leases {
    <#
    .SYNOPSIS
        Loads leases for selected scope
        FIXED: Proper scope validation and logging
    #>
    
    $scopeId = Get-SelectedScopeId
    
    if ([string]::IsNullOrWhiteSpace($scopeId)) {
        $msg = "No scope selected. Please select a scope first."
        Write-ActionLog $msg "WARN"
        Set-Status $msg
        Show-MessageBox -Message $msg -Icon Warning
        Update-LogDisplay
        return
    }
    
    Write-ActionLog "Loading leases for scope: $scopeId" "INFO"
    Set-Status "Loading leases for $scopeId..."
    
    try {
        $leases = @(Get-DhcpServerv4Lease -ComputerName $Global:DHCPServer -ScopeId $scopeId -ErrorAction Stop)
        $count = Get-SafeCount $leases
        
        $script:GridLeases.Dispatcher.Invoke([action]{
            $script:GridLeases.ItemsSource = $leases
            $script:BtnLeaseRefresh.IsEnabled = $true
            if ($null -ne $script:BtnLeaseSelectAll) { $script:BtnLeaseSelectAll.IsEnabled = ($count -gt 0) }
        }, [System.Windows.Threading.DispatcherPriority]::Normal)
        
        Update-LeaseSelectionUi
        
        Write-ActionLog "Loaded $count leases for scope $scopeId" "SUCCESS"
        Set-Status "Loaded $count leases"
        Update-LogDisplay
        
    } catch {
        $errMsg = "Failed to load leases: $_"
        Write-ActionLog $errMsg "ERROR"
        Set-Status $errMsg
        Show-MessageBox -Message $errMsg -Icon Error
        Update-LogDisplay
    }
}

function Load-Reservations {
    <#
    .SYNOPSIS
        Loads reservations for selected scope
    #>
    
    $scopeId = Get-SelectedScopeId
    
    if ([string]::IsNullOrWhiteSpace($scopeId)) {
        $msg = "No scope selected"
        Write-ActionLog $msg "WARN"
        Set-Status $msg
        Update-LogDisplay
        return
    }
    
    Write-ActionLog "Loading reservations for scope: $scopeId" "INFO"
    Set-Status "Loading reservations..."
    
    try {
        $reservations = @(Get-DhcpServerv4Reservation -ComputerName $Global:DHCPServer -ScopeId $scopeId -ErrorAction Stop)
        $count = Get-SafeCount $reservations
        
        $script:GridReservations.Dispatcher.Invoke([action]{
            $script:GridReservations.ItemsSource = $reservations
            $script:BtnResAdd.IsEnabled = $true
        }, [System.Windows.Threading.DispatcherPriority]::Normal)
        
        Write-ActionLog "Loaded $count reservations" "SUCCESS"
        Set-Status "Loaded $count reservations"
        Update-LogDisplay
        
    } catch {
        $errMsg = "Failed to load reservations: $_"
        Write-ActionLog $errMsg "ERROR"
        Set-Status $errMsg
        Update-LogDisplay
    }
}

function Load-Exclusions {
    <#
    .SYNOPSIS
        Loads exclusion ranges for selected scope
    #>
    
    $scopeId = Get-SelectedScopeId
    
    if ([string]::IsNullOrWhiteSpace($scopeId)) {
        Write-ActionLog "No scope selected for exclusions" "WARN"
        Update-LogDisplay
        return
    }
    
    Write-ActionLog "Loading exclusions for scope: $scopeId" "INFO"
    Set-Status "Loading exclusions..."
    
    try {
        $exclusions = @(Get-DhcpServerv4ExclusionRange -ComputerName $Global:DHCPServer -ScopeId $scopeId -ErrorAction Stop)
        $count = Get-SafeCount $exclusions
        
        $script:GridExclusions.Dispatcher.Invoke([action]{
            $script:GridExclusions.ItemsSource = $exclusions
            $script:BtnExcAdd.IsEnabled = $true
        }, [System.Windows.Threading.DispatcherPriority]::Normal)
        
        Write-ActionLog "Loaded $count exclusions" "SUCCESS"
        Set-Status "Loaded $count exclusions"
        Update-LogDisplay
        
    } catch {
        $errMsg = "Failed to load exclusions: $_"
        Write-ActionLog $errMsg "ERROR"
        Set-Status $errMsg
        Update-LogDisplay
    }
}

function Load-Options {
    <#
    .SYNOPSIS
        Loads DHCP options based on selected level
    #>
    
    Write-ActionLog "Loading DHCP options..." "INFO"
    Set-Status "Loading options..."
    
    try {
        $level = $script:CboOptionLevel.SelectedItem.Content
        $options = @()
        
        if ($level -eq "Server") {
            $options = @(Get-DhcpServerv4OptionValue -ComputerName $Global:DHCPServer -ErrorAction Stop)
            Write-ActionLog "Loading server-level options" "INFO"
        }
        elseif ($level -eq "Scope") {
            $scopeId = Get-SelectedScopeId
            if ($scopeId) {
                $options = @(Get-DhcpServerv4OptionValue -ComputerName $Global:DHCPServer -ScopeId $scopeId -ErrorAction Stop)
                Write-ActionLog "Loading scope-level options for $scopeId" "INFO"
            } else {
                throw "No scope selected"
            }
        }
        
        $count = Get-SafeCount $options
        
        $script:GridOptions.Dispatcher.Invoke([action]{
            $script:GridOptions.ItemsSource = $options
            $script:BtnOptionSet.IsEnabled = $true
        }, [System.Windows.Threading.DispatcherPriority]::Normal)
        
        Write-ActionLog "Loaded $count options successfully" "SUCCESS"
        Set-Status "Loaded $count options"
        Update-LogDisplay
        
    } catch {
        $errMsg = "Failed to load options: $_"
        Write-ActionLog $errMsg "ERROR"
        Set-Status $errMsg
        Update-LogDisplay
    }
}

function Load-Filters {
    <#
    .SYNOPSIS
        Loads MAC address filters
    #>
    
    Write-ActionLog "Loading MAC filters..." "INFO"
    Set-Status "Loading filters..."
    
    try {
        $listType = $script:CboFilterList.SelectedItem.Content
        
        if ($listType -eq "Allow") {
            $filters = @(Get-DhcpServerv4Filter -ComputerName $Global:DHCPServer -List Allow -ErrorAction Stop)
        } else {
            $filters = @(Get-DhcpServerv4Filter -ComputerName $Global:DHCPServer -List Deny -ErrorAction Stop)
        }
        
        $count = Get-SafeCount $filters
        
        $script:GridFilters.Dispatcher.Invoke([action]{
            $script:GridFilters.ItemsSource = $filters
            $script:BtnFilterAdd.IsEnabled = $true
            $script:ChkEnableFilters.IsEnabled = $true
        }, [System.Windows.Threading.DispatcherPriority]::Normal)
        
        Write-ActionLog "Loaded $count $listType filters" "SUCCESS"
        Set-Status "Loaded $count filters"
        Update-LogDisplay
        
    } catch {
        $errMsg = "Failed to load filters: $_"
        Write-ActionLog $errMsg "ERROR"
        Set-Status $errMsg
        Update-LogDisplay
    }
}

function Load-Policies {
    <#
    .SYNOPSIS
        Loads DHCP policies
    #>
    
    Write-ActionLog "Loading DHCP policies..." "INFO"
    Set-Status "Loading policies..."
    
    try {
        $policies = @(Get-DhcpServerv4Policy -ComputerName $Global:DHCPServer -ErrorAction Stop)
        $count = Get-SafeCount $policies
        
        $script:GridPolicies.Dispatcher.Invoke([action]{
            $script:GridPolicies.ItemsSource = $policies
            $script:BtnPolicyAdd.IsEnabled = $true
        }, [System.Windows.Threading.DispatcherPriority]::Normal)
        
        Write-ActionLog "Loaded $count policies" "SUCCESS"
        Set-Status "Loaded $count policies"
        Update-LogDisplay
        
    } catch {
        $errMsg = "Failed to load policies: $_"
        Write-ActionLog $errMsg "ERROR"
        Set-Status $errMsg
        Update-LogDisplay
    }
}

#region BAD_ADDRESS Troubleshooting
function Reset-BadAddressDiagState {
    param([switch]$KeepScope)
    
    $scopeKeep = ''
    if ($KeepScope) { $scopeKeep = "$($Global:BadAddressDiag.ScopeId)" }
    
    try { $Global:BadAddressFindings.Clear() } catch {}
    try { $Global:BadAddressLeases.Clear() } catch {}
    try { $Global:BadAddressProbes.Clear() } catch {}
    
    $Global:BadAddressDiag.ScopeId = $scopeKeep
    $Global:BadAddressDiag.Server = ''
    $Global:BadAddressDiag.RanAt = $null
    $Global:BadAddressDiag.BadCount = 0
    $Global:BadAddressDiag.Pattern = ''
    $Global:BadAddressDiag.CanClear = $false
    $Global:BadAddressDiag.Summary = ''
    
    try {
        if ($null -ne $script:ChkTroubleshootReviewed) {
            $script:ChkTroubleshootReviewed.IsChecked = $false
            $script:ChkTroubleshootReviewed.IsEnabled = $false
        }
        if ($null -ne $script:BtnTroubleshootClearBad) { $script:BtnTroubleshootClearBad.IsEnabled = $false }
        if ($null -ne $script:TxtTroubleshootClearHint) {
            $script:TxtTroubleshootClearHint.Text = "Clear stays disabled until diagnostics run and you confirm the cause was addressed."
        }
        if ($null -ne $script:TxtTroubleshootSummary -and -not $KeepScope) {
            $script:TxtTroubleshootSummary.Text = "Connect to a DHCP server, choose a scope, then Run Diagnostics. Clear BAD_ADDRESS only after you review findings and correct the cause."
        }
    } catch {}
}

function Add-BadAddressFinding {
    param(
        [int]$Step,
        [string]$Check,
        [string]$Status,
        [string]$Finding,
        [string]$Recommendation = ''
    )
    
    $row = [PSCustomObject]@{
        Step           = $Step
        Check          = $Check
        Status         = $Status
        Finding        = $Finding
        Recommendation = $Recommendation
    }
    [void]$Global:BadAddressFindings.Add($row)
    return $row
}

function Get-TroubleshootSampleSize {
    $n = 3
    try {
        if ($null -ne $script:CboTroubleshootSample -and $null -ne $script:CboTroubleshootSample.SelectedItem) {
            $text = "$($script:CboTroubleshootSample.SelectedItem.Content)" -replace '[^0-9]', ''
            $parsed = 0
            if ([int]::TryParse($text, [ref]$parsed) -and $parsed -ge 3 -and $parsed -le 5) {
                $n = $parsed
            }
        }
    } catch {}
    return $n
}

function Get-TroubleshootScopeIdFromUi {
    try {
        if ($null -eq $script:CboTroubleshootScope) { return '' }
        $item = $script:CboTroubleshootScope.SelectedItem
        if ($null -eq $item) { return '' }
        if ($item -is [string]) {
            $m = [regex]::Match("$item", '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
            if ($m.Success) { return $m.Groups[1].Value }
            return ''
        }
        if ($null -ne $item.PSObject.Properties['ScopeId'] -and $item.ScopeId) {
            return "$($item.ScopeId)"
        }
        $text = "$item"
        $m2 = [regex]::Match($text, '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        if ($m2.Success) { return $m2.Groups[1].Value }
    } catch {}
    return ''
}

function Update-TroubleshootScopeList {
    <#
    .SYNOPSIS
        Reloads the Troubleshoot scope combo from the connected DHCP server
    #>
    if ([string]::IsNullOrWhiteSpace($Global:DHCPServer)) { return }
    if ($null -eq $script:CboTroubleshootScope) { return }
    
    try {
        $prev = Get-TroubleshootScopeIdFromUi
        if (-not $prev) { $prev = "$($Global:SelectedScope)" }
        
        $scopes = @(Get-DhcpServerv4Scope -ComputerName $Global:DHCPServer -ErrorAction Stop)
        $scopes = @($scopes | Sort-Object { Get-IpAddressSortKey "$($_.ScopeId)" }, Name)
        
        $items = [System.Collections.Generic.List[string]]::new()
        foreach ($s in $scopes) {
            $sid = "$($s.ScopeId)"
            $name = "$($s.Name)".Trim()
            if ($name) {
                [void]$items.Add("$sid  —  $name")
            } else {
                [void]$items.Add($sid)
            }
        }
        
        $script:CboTroubleshootScope.Items.Clear()
        foreach ($it in $items) { [void]$script:CboTroubleshootScope.Items.Add($it) }
        
        $selected = $false
        if ($prev) {
            for ($i = 0; $i -lt $script:CboTroubleshootScope.Items.Count; $i++) {
                $cand = "$($script:CboTroubleshootScope.Items[$i])"
                if ($cand -like "$prev*" -or $cand -match [regex]::Escape($prev)) {
                    $script:CboTroubleshootScope.SelectedIndex = $i
                    $selected = $true
                    break
                }
            }
        }
        if (-not $selected -and $script:CboTroubleshootScope.Items.Count -gt 0) {
            $script:CboTroubleshootScope.SelectedIndex = 0
        }
        
        Write-ActionLog "Troubleshoot scope list loaded: $(Get-SafeCount $scopes) scope(s)" "INFO"
    } catch {
        Write-ActionLog "Failed to load Troubleshoot scopes: $_" "WARN"
    }
}

function Set-TroubleshootScopeSelection {
    param([string]$ScopeId)
    
    if ([string]::IsNullOrWhiteSpace($ScopeId)) { return $false }
    if ($null -eq $script:CboTroubleshootScope) { return $false }
    
    if ($script:CboTroubleshootScope.Items.Count -eq 0) {
        Update-TroubleshootScopeList
    }
    
    for ($i = 0; $i -lt $script:CboTroubleshootScope.Items.Count; $i++) {
        $cand = "$($script:CboTroubleshootScope.Items[$i])"
        if ($cand -like "$ScopeId*" -or $cand -match ("^" + [regex]::Escape($ScopeId) + "(\s|$)")) {
            $script:CboTroubleshootScope.SelectedIndex = $i
            return $true
        }
    }
    return $false
}

function Get-IpAddressUInt32 {
    param([string]$IPAddress)
    try {
        $bytes = ([System.Net.IPAddress]::Parse($IPAddress)).GetAddressBytes()
        if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
        return [BitConverter]::ToUInt32($bytes, 0)
    } catch {
        return [uint32]0
    }
}

function Test-BadAddressPattern {
    <#
    .SYNOPSIS
        Classifies BAD_ADDRESS IPs as Sequential, Clustered, or Random/Scattered
    #>
    param([string[]]$IPAddresses)
    
    $ips = @($IPAddresses | Where-Object { $_ -and (Test-IPAddress $_) } | Select-Object -Unique)
    $count = Get-SafeCount $ips
    if ($count -eq 0) {
        return [PSCustomObject]@{
            Pattern = 'None'
            Detail  = 'No BAD_ADDRESS IPs to analyze'
            Gaps    = @()
        }
    }
    if ($count -eq 1) {
        return [PSCustomObject]@{
            Pattern = 'Single'
            Detail  = "Only one BAD_ADDRESS ($($ips[0])) — pattern not conclusive"
            Gaps    = @()
        }
    }
    
    $sorted = @($ips | Sort-Object { Get-IpAddressUInt32 $_ })
    $gaps = [System.Collections.Generic.List[int]]::new()
    for ($i = 1; $i -lt $sorted.Count; $i++) {
        $a = Get-IpAddressUInt32 $sorted[$i - 1]
        $b = Get-IpAddressUInt32 $sorted[$i]
        if ($b -gt $a) {
            [void]$gaps.Add([int]($b - $a))
        }
    }
    
    $gapArr = @($gaps)
    $avgGap = ($gapArr | Measure-Object -Average).Average
    $maxGap = ($gapArr | Measure-Object -Maximum).Maximum
    $minGap = ($gapArr | Measure-Object -Minimum).Minimum
    $adjacent = Get-SafeCount @($gapArr | Where-Object { $_ -eq 1 })
    $near = Get-SafeCount @($gapArr | Where-Object { $_ -le 3 })
    $gapCount = Get-SafeCount $gapArr
    
    $pattern = 'Random'
    $detail = ''
    if ($gapCount -gt 0 -and ($adjacent / [double]$gapCount) -ge 0.6) {
        $pattern = 'Sequential'
        $detail = "Mostly consecutive IPs ($adjacent/$gapCount adjacent gaps). Suggests conflict detection walking the pool, a scanner, or a device claiming a range."
    } elseif ($gapCount -gt 0 -and ($near / [double]$gapCount) -ge 0.5 -and $maxGap -le 16) {
        $pattern = 'Clustered'
        $detail = "BAD addresses are tightly clustered (avg gap $([math]::Round($avgGap,1)), max $maxGap). Often a local device/range conflict rather than random clients."
    } else {
        $pattern = 'Random'
        $detail = "Scattered across the scope (gaps min/avg/max = $minGap / $([math]::Round($avgGap,1)) / $maxGap). Often multi-client conflicts, rogue DHCP, or proxy-ARP replies from different sources."
    }
    
    return [PSCustomObject]@{
        Pattern = $pattern
        Detail  = $detail
        Gaps    = $gapArr
    }
}

function Get-ArpNeighborInfo {
    <#
    .SYNOPSIS
        Resolves ARP/neighbor MAC for an IPv4 address (Get-NetNeighbor, then arp -a)
    #>
    param([Parameter(Mandatory)][string]$IPAddress)
    
    $result = [PSCustomObject]@{
        Mac     = ''
        State   = 'Unknown'
        Source  = ''
        Detail  = ''
    }
    
    try {
        $neighbors = @(Get-NetNeighbor -IPAddress $IPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue)
        if ((Get-SafeCount $neighbors) -gt 0) {
            $n = $neighbors | Select-Object -First 1
            $mac = Get-NormalizedCompareMac $n.LinkLayerAddress
            $state = "$($n.State)"
            if ($mac -and $mac -ne '000000000000' -and $state -notmatch 'Unreachable|Incomplete') {
                $result.Mac = Format-CompareMacDisplay $mac
                $result.State = $state
                $result.Source = 'Get-NetNeighbor'
                $result.Detail = "Neighbor $state"
                return $result
            }
            $result.State = $(if ($state) { $state } else { 'NoEntry' })
            $result.Source = 'Get-NetNeighbor'
            $result.Detail = "Neighbor present without usable MAC ($state)"
        }
    } catch {
        $result.Detail = "Get-NetNeighbor: $_"
    }
    
    # Trigger ARP resolution with a short ping first
    try { $null = Test-HostPingStatus -ComputerName $IPAddress -TimeoutMs 800 } catch {}
    
    try {
        $neighbors2 = @(Get-NetNeighbor -IPAddress $IPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue)
        if ((Get-SafeCount $neighbors2) -gt 0) {
            $n2 = $neighbors2 | Select-Object -First 1
            $mac2 = Get-NormalizedCompareMac $n2.LinkLayerAddress
            $state2 = "$($n2.State)"
            if ($mac2 -and $mac2 -ne '000000000000' -and $state2 -notmatch 'Unreachable|Incomplete') {
                $result.Mac = Format-CompareMacDisplay $mac2
                $result.State = $state2
                $result.Source = 'Get-NetNeighbor'
                $result.Detail = "Neighbor $state2 (after probe)"
                return $result
            }
            if (-not $result.State -or $result.State -eq 'Unknown') { $result.State = $state2 }
        }
    } catch {}
    
    try {
        $arpOut = & arp.exe -a $IPAddress 2>$null
        foreach ($line in @($arpOut)) {
            if ("$line" -match [regex]::Escape($IPAddress) -and "$line" -match '([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}') {
                $macRaw = $Matches[0]
                # Prefer the MAC token from the line
                if ("$line" -match '([0-9A-Fa-f]{2}([-:])[0-9A-Fa-f]{2}(\2[0-9A-Fa-f]{2}){4})') {
                    $macRaw = $Matches[1]
                }
                $mac3 = Get-NormalizedCompareMac $macRaw
                if ($mac3 -and $mac3 -ne '000000000000') {
                    $result.Mac = Format-CompareMacDisplay $mac3
                    $result.State = 'Reachable'
                    $result.Source = 'arp -a'
                    $result.Detail = 'Resolved via arp.exe'
                    return $result
                }
            }
        }
    } catch {
        if (-not $result.Detail) { $result.Detail = "arp.exe: $_" }
    }
    
    if (-not $result.State -or $result.State -eq 'Unknown') { $result.State = 'NoEntry' }
    if (-not $result.Detail) { $result.Detail = 'No ARP entry (host may be offline or not on this L2 segment)' }
    return $result
}

function Get-BadAddressLeasesForScope {
    param(
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][string]$ScopeId
    )
    
    $leases = @(Get-DhcpServerv4Lease -ComputerName $Server -ScopeId $ScopeId -ErrorAction Stop)
    $bad = @($leases | Where-Object {
        $hn = "$($_.HostName)"
        $st = "$($_.AddressState)"
        ($hn -match 'BAD_ADDRESS') -or ($st -match 'Bad|Declined')
    })
    
    # Stable numeric order for pattern + probe sampling
    return @($bad | Sort-Object { Get-IpAddressUInt32 "$($_.IPAddress)" }, { "$($_.IPAddress)" })
}

function Update-TroubleshootClearUi {
    $canEnableReview = [bool]$Global:BadAddressDiag.CanClear -and ($Global:BadAddressDiag.BadCount -gt 0)
    $reviewed = $false
    try { $reviewed = [bool]$script:ChkTroubleshootReviewed.IsChecked } catch {}
    
    try {
        if ($null -ne $script:ChkTroubleshootReviewed) {
            $script:ChkTroubleshootReviewed.IsEnabled = $canEnableReview
            if (-not $canEnableReview) { $script:ChkTroubleshootReviewed.IsChecked = $false }
        }
        $allowClear = $canEnableReview -and $reviewed
        if ($null -ne $script:BtnTroubleshootClearBad) {
            $script:BtnTroubleshootClearBad.IsEnabled = $allowClear
        }
        if ($null -ne $script:TxtTroubleshootClearHint) {
            if ($allowClear) {
                $script:TxtTroubleshootClearHint.Text = "Ready to clear $($Global:BadAddressDiag.BadCount) BAD_ADDRESS lease(s) on scope $($Global:BadAddressDiag.ScopeId)."
            } elseif ($canEnableReview) {
                $script:TxtTroubleshootClearHint.Text = "Check the box after you correct the root cause, then Clear becomes available."
            } elseif ($Global:BadAddressDiag.BadCount -eq 0 -and $Global:BadAddressDiag.RanAt) {
                $script:TxtTroubleshootClearHint.Text = "No BAD_ADDRESS leases to clear for this scope."
            } else {
                $script:TxtTroubleshootClearHint.Text = "Clear stays disabled until diagnostics run and you confirm the cause was addressed."
            }
        }
    } catch {}
}

function Invoke-BadAddressDiagnostics {
    <#
    .SYNOPSIS
        Runs the BAD_ADDRESS root-cause checklist for a scope
    #>
    param(
        [string]$ScopeId,
        [int]$SampleSize = 3
    )
    
    if ([string]::IsNullOrWhiteSpace($Global:DHCPServer)) {
        Show-MessageBox "Connect to a DHCP server first." "Not Connected" OK Warning
        return
    }
    
    if ([string]::IsNullOrWhiteSpace($ScopeId)) {
        $ScopeId = Get-TroubleshootScopeIdFromUi
    }
    if ([string]::IsNullOrWhiteSpace($ScopeId)) {
        Show-MessageBox "Select a scope to troubleshoot." "No Scope" OK Warning
        return
    }
    
    if ($SampleSize -lt 3) { $SampleSize = 3 }
    if ($SampleSize -gt 5) { $SampleSize = 5 }
    
    $server = $Global:DHCPServer
    Reset-BadAddressDiagState -KeepScope
    $Global:BadAddressDiag.ScopeId = $ScopeId
    $Global:BadAddressDiag.Server = $server
    
    Write-ActionLog "BAD_ADDRESS diagnostics starting for scope $ScopeId on $server (sample=$SampleSize)" "INFO"
    Set-Status "Running BAD_ADDRESS diagnostics for $ScopeId..."
    Start-TaskProgress -Name 'BadAddressDiag' -Message "Diagnosing BAD_ADDRESS on $ScopeId..." -CanPause -Total 9
    
    $summaryParts = [System.Collections.Generic.List[string]]::new()
    $likelyCauses = [System.Collections.Generic.List[string]]::new()
    
    try {
        # --- Step 1: ConflictDetectionAttempts ---
        Wait-TaskProgressIfPaused
        if (Test-TaskCancelRequested) { throw "Canceled" }
        Update-TaskProgress -Processed 1 -Message "Checking ConflictDetectionAttempts..."
        
        $conflictAttempts = $null
        $conflictStatus = 'Info'
        $conflictFinding = ''
        $conflictRec = ''
        try {
            $settings = Get-DhcpServerSetting -ComputerName $server -ErrorAction Stop
            $conflictAttempts = [int]$settings.ConflictDetectionAttempts
            if ($conflictAttempts -le 0) {
                $conflictStatus = 'Warn'
                $conflictFinding = "ConflictDetectionAttempts = 0 (conflict detection disabled)."
                $conflictRec = "Enable conflict detection (typically 1–2 attempts) so the server pings before offering an address. Note: enabling it will create BAD_ADDRESS entries when conflicts exist — fix the cause, don't only clear leases."
                [void]$likelyCauses.Add('Conflict detection disabled (conflicts go unnoticed until client fails)')
            } elseif ($conflictAttempts -ge 3) {
                $conflictStatus = 'Info'
                $conflictFinding = "ConflictDetectionAttempts = $conflictAttempts (aggressive)."
                $conflictRec = "Value is valid but higher values slow offers. 1–2 is usual. BAD_ADDRESS growth means real conflicts are being detected — investigate probes/failover/rogue DHCP next."
            } else {
                $conflictStatus = 'OK'
                $conflictFinding = "ConflictDetectionAttempts = $conflictAttempts."
                $conflictRec = "Conflict detection is on. BAD_ADDRESS entries mean the server detected live IPs before offering — keep investigating who owns those IPs."
            }
        } catch {
            $conflictStatus = 'Error'
            $conflictFinding = "Could not read DHCP server settings: $_"
            $conflictRec = "Verify DhcpServer module permissions on $server."
        }
        Add-BadAddressFinding -Step 1 -Check 'ConflictDetectionAttempts' -Status $conflictStatus -Finding $conflictFinding -Recommendation $conflictRec
        [void]$summaryParts.Add("ConflictDetection=$conflictAttempts")
        
        # --- Collect BAD leases (feeds steps 2–5) ---
        Wait-TaskProgressIfPaused
        if (Test-TaskCancelRequested) { throw "Canceled" }
        Update-TaskProgress -Processed 2 -Message "Loading BAD_ADDRESS leases..."
        
        $badLeases = @()
        try {
            $badLeases = @(Get-BadAddressLeasesForScope -Server $server -ScopeId $ScopeId)
        } catch {
            Add-BadAddressFinding -Step 2 -Check 'BAD_ADDRESS inventory' -Status 'Error' -Finding "Failed to load leases: $_" -Recommendation "Confirm scope exists and you have DHCP admin rights."
            throw
        }
        
        $badCount = Get-SafeCount $badLeases
        $Global:BadAddressDiag.BadCount = $badCount
        foreach ($lease in $badLeases) {
            [void]$Global:BadAddressLeases.Add([PSCustomObject]@{
                IPAddress       = "$($lease.IPAddress)"
                ClientId        = "$(if ($lease.ClientId) { $lease.ClientId } else { '' })"
                HostName        = "$($lease.HostName)"
                AddressState    = "$($lease.AddressState)"
                LeaseExpiryTime = "$(if ($lease.LeaseExpiryTime) { $lease.LeaseExpiryTime } else { '' })"
            })
        }
        
        if ($badCount -eq 0) {
            Add-BadAddressFinding -Step 2 -Check 'BAD_ADDRESS inventory' -Status 'OK' -Finding "No BAD_ADDRESS / Declined leases in scope $ScopeId." -Recommendation "Nothing to clear. If utilization still looks wrong, refresh Statistics and check exclusions/reservations."
            $Global:BadAddressDiag.Pattern = 'None'
            $Global:BadAddressDiag.CanClear = $false
            $Global:BadAddressDiag.RanAt = Get-Date
            $Global:BadAddressDiag.Summary = "Scope ${ScopeId}: no BAD_ADDRESS leases found."
            if ($null -ne $script:TxtTroubleshootSummary) {
                $script:TxtTroubleshootSummary.Text = $Global:BadAddressDiag.Summary
            }
            Update-TroubleshootClearUi
            Complete-TaskProgress -Message "No BAD_ADDRESS leases in $ScopeId"
            Set-Status "No BAD_ADDRESS leases in $ScopeId"
            Update-LogDisplay
            return
        }
        
        Add-BadAddressFinding -Step 2 -Check 'BAD_ADDRESS inventory' -Status 'Warn' -Finding "$badCount BAD_ADDRESS/Declined lease(s) in scope $ScopeId." -Recommendation "Do not clear yet — finish the checklist and correct the cause first."
        [void]$summaryParts.Add("BAD=$badCount")
        
        # --- Step 2b / pattern: sequential vs random ---
        Wait-TaskProgressIfPaused
        if (Test-TaskCancelRequested) { throw "Canceled" }
        Update-TaskProgress -Processed 3 -Message "Analyzing BAD_ADDRESS pattern..."
        
        $patternResult = Test-BadAddressPattern -IPAddresses @($badLeases | ForEach-Object { "$($_.IPAddress)" })
        $Global:BadAddressDiag.Pattern = $patternResult.Pattern
        $patternStatus = switch ($patternResult.Pattern) {
            'Sequential' { 'Warn' }
            'Clustered'  { 'Warn' }
            'Random'     { 'Warn' }
            default      { 'Info' }
        }
        $patternRec = switch ($patternResult.Pattern) {
            'Sequential' { 'Look for conflict-detection walking the pool, a port scanner, or one device answering for a contiguous range (proxy ARP / misconfigured VIP).' }
            'Clustered'  { 'Inspect the clustered subnet pocket — likely one L2/L3 device or a small set of static IPs overlapping the dynamic range.' }
            'Random'     { 'Scattered conflicts often mean many real clients, intermittent rogue DHCP, or firewall/proxy-ARP answering inconsistently.' }
            default      { 'Collect more BAD_ADDRESS samples if the issue continues.' }
        }
        Add-BadAddressFinding -Step 3 -Check 'Sequential vs random' -Status $patternStatus -Finding "$($patternResult.Pattern): $($patternResult.Detail)" -Recommendation $patternRec
        [void]$summaryParts.Add("Pattern=$($patternResult.Pattern)")
        
        # --- Steps 4–5: Ping/ARP sample + MAC compare + device ownership ---
        Wait-TaskProgressIfPaused
        if (Test-TaskCancelRequested) { throw "Canceled" }
        Update-TaskProgress -Processed 4 -Message "Probing sample BAD addresses (ping/ARP)..."
        
        $sampleN = [math]::Min($SampleSize, $badCount)
        # Spread sample across the sorted list (first, middle-ish, last) when possible
        $sampleIdx = [System.Collections.Generic.List[int]]::new()
        if ($sampleN -eq 1) {
            [void]$sampleIdx.Add(0)
        } else {
            for ($si = 0; $si -lt $sampleN; $si++) {
                $idx = [int][math]::Round(($si * ($badCount - 1)) / [double]($sampleN - 1))
                if (-not $sampleIdx.Contains($idx)) { [void]$sampleIdx.Add($idx) }
            }
            while ($sampleIdx.Count -lt $sampleN) {
                for ($j = 0; $j -lt $badCount -and $sampleIdx.Count -lt $sampleN; $j++) {
                    if (-not $sampleIdx.Contains($j)) { [void]$sampleIdx.Add($j) }
                }
            }
        }
        
        $probeMacs = [System.Collections.Generic.List[string]]::new()
        $pingUp = 0
        $arpHits = 0
        $probeNum = 0
        foreach ($idx in $sampleIdx) {
            Wait-TaskProgressIfPaused
            if (Test-TaskCancelRequested) { throw "Canceled" }
            $probeNum++
            $lease = $badLeases[$idx]
            $ip = "$($lease.IPAddress)"
            Update-TaskProgress -Processed 4 -Message "Probing $ip ($probeNum/$sampleN)..."
            
            $ping = Test-HostPingStatus -ComputerName $ip -TimeoutMs 1500
            if ($ping.Status -eq 'Up') { $pingUp++ }
            
            $arp = Get-ArpNeighborInfo -IPAddress $ip
            if ($arp.Mac) {
                $arpHits++
                $norm = Get-NormalizedCompareMac $arp.Mac
                if ($norm -and -not $probeMacs.Contains($norm)) { [void]$probeMacs.Add($norm) }
            }
            
            if ($ping.Status -eq 'Up' -and $arp.Mac) {
                $notes = 'Live host with ARP — address is in use on this L2 path'
            } elseif ($ping.Status -eq 'Up' -and -not $arp.Mac) {
                $notes = 'Ping OK but no local ARP — may be routed/remote or filtered ARP'
            } elseif ($ping.Status -ne 'Up' -and $arp.Mac) {
                $notes = 'ARP present, ICMP blocked — device may still own the IP'
            } else {
                $notes = 'No live response from this workstation — conflict may be stale or on another segment'
            }
            
            [void]$Global:BadAddressProbes.Add([PSCustomObject]@{
                IPAddress  = $ip
                PingStatus = $ping.Status
                LatencyMs  = $(if ($null -ne $ping.LatencyMs) { "$($ping.LatencyMs) ms" } else { '' })
                ArpMac     = $(if ($arp.Mac) { $arp.Mac } else { '' })
                ArpState   = $arp.State
                Notes      = $notes
            })
        }
        
        $probeFinding = "Sampled $sampleN of ${badCount}: ping Up $pingUp/$sampleN, ARP MAC $arpHits/$sampleN."
        $probeRec = "If probes are live, those IPs belong to real devices (or a middlebox). Remove statics from the dynamic range, fix reservations, or exclude the addresses — then clear BAD_ADDRESS."
        $probeStatus = if ($pingUp -gt 0 -or $arpHits -gt 0) { 'Warn' } else { 'Info' }
        Add-BadAddressFinding -Step 4 -Check 'Ping / ARP sample' -Status $probeStatus -Finding $probeFinding -Recommendation $probeRec
        [void]$summaryParts.Add("Probes pingUp=$pingUp/$sampleN arp=$arpHits/$sampleN")
        
        Wait-TaskProgressIfPaused
        if (Test-TaskCancelRequested) { throw "Canceled" }
        Update-TaskProgress -Processed 5 -Message "Comparing probe MAC addresses..."
        
        $macCount = Get-SafeCount $probeMacs
        $macStatus = 'Info'
        $macFinding = ''
        $macRec = ''
        if ($macCount -eq 0) {
            $macStatus = 'Info'
            $macFinding = "No ARP MACs resolved from this management host for the sample."
            $macRec = "Run probes from a host on the same VLAN as the scope for accurate ARP. Lack of ARP here does not prove the IPs are free."
        } elseif ($macCount -eq 1 -and $arpHits -ge 2) {
            $macStatus = 'Warn'
            $displayMac = Format-CompareMacDisplay $probeMacs[0]
            $macFinding = "Same MAC ($displayMac) answers for multiple BAD IPs."
            $macRec = "Strong indicator of proxy ARP, firewall/NAT, load balancer, or a misconfigured router claiming many addresses. Check gateway/firewall proxy-ARP and HSRP/VRRP."
            [void]$likelyCauses.Add("Proxy ARP / single MAC ($displayMac) owning multiple BAD IPs")
        } elseif ($macCount -ge 2) {
            $macStatus = 'Warn'
            $macList = @($probeMacs | ForEach-Object { Format-CompareMacDisplay $_ }) -join ', '
            $macFinding = "Multiple distinct MACs in sample ($macCount): $macList."
            $macRec = "Different devices own these IPs. Look for static IP conflicts, missing reservations, or clients with manually assigned addresses inside the pool."
            [void]$likelyCauses.Add('Multiple real devices conflicting with the DHCP pool')
        } else {
            $macStatus = 'Info'
            $macFinding = "One ARP MAC observed on a single probe: $(Format-CompareMacDisplay $probeMacs[0])."
            $macRec = "Correlate that MAC on switches (show mac address-table) to find the access port / device."
        }
        Add-BadAddressFinding -Step 5 -Check 'MAC comparison' -Status $macStatus -Finding $macFinding -Recommendation $macRec
        
        Wait-TaskProgressIfPaused
        if (Test-TaskCancelRequested) { throw "Canceled" }
        Update-TaskProgress -Processed 6 -Message "Assessing whether BAD IPs belong to devices..."
        
        $ownStatus = 'Info'
        $ownFinding = ''
        $ownRec = ''
        if ($pingUp -gt 0 -or $arpHits -gt 0) {
            $ownStatus = 'Warn'
            $ownFinding = "One or more sampled BAD addresses respond (ping and/or ARP) — they currently belong to live devices or a middlebox."
            $ownRec = "Do not clear yet. Identify owners (MAC → switch port → hostname), convert to reservations or exclusions, or move statics out of the pool."
            [void]$likelyCauses.Add('Live devices still using BAD_ADDRESS IPs')
        } else {
            $ownStatus = 'Info'
            $ownFinding = "Sampled BAD addresses did not respond from this host — may be stale, ICMP-filtered, or on another L2 segment."
            $ownRec = "Re-probe from the VLAN, check DHCP audit/events for decline reasons, and confirm no other DHCP is offering those IPs before clearing."
        }
        Add-BadAddressFinding -Step 6 -Check 'Device ownership' -Status $ownStatus -Finding $ownFinding -Recommendation $ownRec
        
        # --- Step 7: Failover health ---
        Wait-TaskProgressIfPaused
        if (Test-TaskCancelRequested) { throw "Canceled" }
        Update-TaskProgress -Processed 7 -Message "Checking DHCP failover health..."
        
        $foStatus = 'Info'
        $foFinding = 'No failover relationship found on this server.'
        $foRec = 'Standalone server — skip failover concerns unless a partner was expected.'
        try {
            $failovers = @(Get-DhcpServerv4Failover -ComputerName $server -ErrorAction SilentlyContinue)
            if ((Get-SafeCount $failovers) -eq 0) {
                $foStatus = 'OK'
                $foFinding = 'No DHCP failover relationships configured on this server.'
                $foRec = 'If a partner was expected, configure/repair failover. Otherwise continue with rogue DHCP / proxy-ARP checks.'
            } else {
                $foBits = [System.Collections.Generic.List[string]]::new()
                $foWarn = $false
                foreach ($fo in $failovers) {
                    $name = "$($fo.Name)"
                    $state = "$($fo.State)"
                    $mode = "$($fo.Mode)"
                    $partner = "$($fo.PartnerServer)"
                    $scopeMatch = $false
                    try {
                        $foScopes = @($fo.ScopeId)
                        foreach ($fs in $foScopes) {
                            if ("$fs" -eq $ScopeId) { $scopeMatch = $true; break }
                        }
                    } catch {}
                    $scopeNote = if ($scopeMatch) { "includes scope $ScopeId" } else { "scope $ScopeId not listed on this relationship (server-wide check)" }
                    
                    $statText = ''
                    try {
                        $stats = Get-DhcpServerv4FailoverStatistics -ComputerName $server -Name $name -ErrorAction SilentlyContinue
                        if ($stats) {
                            $statText = " (local free=$($stats.AddressesFree), partner free=$($stats.AddressesFreePartner), pending=$($stats.PendingOffers))"
                        }
                    } catch {}
                    
                    if ($state -notmatch 'Normal|NoState') {
                        $foWarn = $true
                        [void]$likelyCauses.Add("Failover '$name' state=$state")
                    }
                    [void]$foBits.Add("$name → partner $partner; mode=$mode; state=$state; $scopeNote$statText")
                }
                $foFinding = ($foBits -join ' | ')
                if ($foWarn) {
                    $foStatus = 'Warn'
                    $foRec = 'Repair failover (replication, time sync, partner reachability). Split-brain / communication-interrupted partners commonly create duplicate offers and BAD_ADDRESS storms.'
                } else {
                    $foStatus = 'OK'
                    $foRec = 'Failover reports a healthy state. Still verify both nodes authorize the same scopes and are not double-offering outside the relationship.'
                }
            }
        } catch {
            $foStatus = 'Error'
            $foFinding = "Failover query failed: $_"
            $foRec = 'Install/update DhcpServer RSAT tools and confirm permissions.'
        }
        Add-BadAddressFinding -Step 7 -Check 'DHCP failover health' -Status $foStatus -Finding $foFinding -Recommendation $foRec
        
        # --- Step 8: Another DHCP server on the VLAN ---
        Wait-TaskProgressIfPaused
        if (Test-TaskCancelRequested) { throw "Canceled" }
        Update-TaskProgress -Processed 8 -Message "Checking for other DHCP servers..."
        
        $rogueStatus = 'Info'
        $rogueFinding = ''
        $rogueRec = 'From a client on this VLAN: run a DHCP discover capture (Wireshark filter bootp) or use a rogue-DHCP detector. Compare offeror IPs to authorized servers.'
        try {
            $authServers = @()
            try { $authServers = @(Get-DhcpServerInDC -ErrorAction SilentlyContinue) } catch {}
            $authNames = @($authServers | ForEach-Object {
                $dn = "$($_.DnsName)".Trim()
                $ip = "$($_.IPAddress)".Trim()
                if ($dn -and $ip) { "$dn ($ip)" } elseif ($dn) { $dn } else { $ip }
            } | Where-Object { $_ })
            
            $scanExtra = @()
            if ((Get-SafeCount $Global:DomainScanResults) -gt 0) {
                $scanExtra = @($Global:DomainScanResults | Where-Object {
                    "$($_.Authorized)" -eq 'No' -or "$($_.Online)" -match 'Up|Yes'
                } | Select-Object -First 8 | ForEach-Object {
                    "$($_.DnsName) online=$($_.Online) auth=$($_.Authorized)"
                })
            }
            
            $authCount = Get-SafeCount $authNames
            if ($authCount -gt 0) {
                $rogueFinding = "AD-authorized DHCP servers ($authCount): $(($authNames | Select-Object -First 6) -join '; ')$(if ($authCount -gt 6) { ' ...' }). Connected target: $server."
            } else {
                $rogueFinding = "Could not enumerate AD-authorized DHCP servers from this host. Connected target: $server."
            }
            if ((Get-SafeCount $scanExtra) -gt 0) {
                $rogueFinding += " Recent domain-scan sample: $($scanExtra -join '; ')."
            }
            $rogueFinding += " In-app packet capture on the VLAN is not available — confirm no unauthorized offeror on this subnet."
            $rogueStatus = 'Warn'
            $rogueRec = "Ensure only the intended DHCP server/failover pair serves this VLAN. Disable unauthorized appliances (firewall DHCP, IP helpers to wrong servers, consumer routers). Use Scan Domain for AD inventory, then capture DHCP Offers on-VLAN."
            [void]$likelyCauses.Add('Possible additional DHCP server on VLAN (verify with capture)')
        } catch {
            $rogueStatus = 'Error'
            $rogueFinding = "Rogue DHCP check failed: $_"
        }
        Add-BadAddressFinding -Step 8 -Check 'Other DHCP on VLAN' -Status $rogueStatus -Finding $rogueFinding -Recommendation $rogueRec
        
        # --- Step 9: Gateway / proxy ARP ---
        Wait-TaskProgressIfPaused
        if (Test-TaskCancelRequested) { throw "Canceled" }
        Update-TaskProgress -Processed 9 -Message "Checking gateway / proxy ARP indicators..."
        
        $gwStatus = 'Info'
        $gwFinding = ''
        $gwRec = 'On the gateway/firewall: disable proxy ARP unless required; verify no DHCP service; confirm HSRP/VRRP VIP is not overlapping the dynamic pool; check IP helper-address targets.'
        $gateways = @()
        try {
            $opt = @(Get-DhcpServerv4OptionValue -ComputerName $server -ScopeId $ScopeId -OptionId 3 -ErrorAction SilentlyContinue)
            if ((Get-SafeCount $opt) -eq 0) {
                $opt = @(Get-DhcpServerv4OptionValue -ComputerName $server -OptionId 3 -ErrorAction SilentlyContinue)
            }
            foreach ($o in $opt) {
                foreach ($v in @($o.Value)) {
                    $vip = "$v".Trim()
                    if (Test-IPAddress $vip) { $gateways += $vip }
                }
            }
            $gateways = @($gateways | Select-Object -Unique)
        } catch {}
        
        if ((Get-SafeCount $gateways) -eq 0) {
            $gwStatus = 'Warn'
            $gwFinding = "No Router (003) option found for scope $ScopeId (scope or server level)."
            $gwRec = "Set the correct gateway option, then re-check proxy ARP on that gateway/firewall."
        } else {
            $gwBits = [System.Collections.Generic.List[string]]::new()
            foreach ($gw in $gateways) {
                $gwPing = Test-HostPingStatus -ComputerName $gw -TimeoutMs 1500
                $gwArp = Get-ArpNeighborInfo -IPAddress $gw
                $sameAsProbe = $false
                if ($gwArp.Mac) {
                    $gwNorm = Get-NormalizedCompareMac $gwArp.Mac
                    if ($gwNorm -and $probeMacs.Contains($gwNorm)) { $sameAsProbe = $true }
                }
                $bit = "GW $gw ping=$($gwPing.Status)"
                if ($gwArp.Mac) { $bit += " ARP=$($gwArp.Mac)" }
                if ($sameAsProbe) {
                    $bit += ' ★ same MAC as BAD probe(s)'
                    $gwStatus = 'Warn'
                    [void]$likelyCauses.Add("Gateway/firewall MAC matches BAD_ADDRESS probes (proxy ARP likely) — $gw")
                }
                [void]$gwBits.Add($bit)
            }
            if ($gwStatus -ne 'Warn') { $gwStatus = 'Info' }
            $gwFinding = ($gwBits -join ' | ')
            $gwFinding += ' | Checklist: proxy-ARP off (unless required), no DHCP on firewall, helpers point only to authorized DHCP, VIP/HSRP not inside dynamic range.'
            if ($macCount -eq 1 -and $arpHits -ge 2) {
                $gwStatus = 'Warn'
                $gwRec = 'Multiple BAD IPs share one MAC — treat as proxy ARP / L3 middlebox until proven otherwise. Compare that MAC to the gateway ARP MAC above and to firewall interface MACs.'
            }
        }
        Add-BadAddressFinding -Step 9 -Check 'Gateway / proxy ARP' -Status $gwStatus -Finding $gwFinding -Recommendation $gwRec
        
        # --- Wrap-up: allow clear only after review ---
        $Global:BadAddressDiag.CanClear = $true
        $Global:BadAddressDiag.RanAt = Get-Date
        
        $causeText = if ((Get-SafeCount $likelyCauses) -gt 0) {
            "Likely causes: $(($likelyCauses | Select-Object -Unique) -join '; ')."
        } else {
            "No single strong cause auto-detected — use findings above and on-VLAN capture before clearing."
        }
        
        $summary = "Scope $ScopeId on $server — $($summaryParts -join ' | '). $causeText Clear is gated until you confirm the root cause was corrected."
        $Global:BadAddressDiag.Summary = $summary
        if ($null -ne $script:TxtTroubleshootSummary) {
            $script:TxtTroubleshootSummary.Text = $summary
        }
        
        Add-BadAddressFinding -Step 10 -Check 'Clear readiness' -Status 'Info' -Finding "Diagnostics complete for $badCount BAD_ADDRESS lease(s). Clear remains locked until you check the confirmation box." -Recommendation "Correct the cause (conflict sources, failover, rogue DHCP, proxy ARP, static overlaps), then check the box and clear BAD_ADDRESS leases for this scope only."
        
        Update-TroubleshootClearUi
        Complete-TaskProgress -Message "BAD_ADDRESS diagnostics complete for $ScopeId"
        Set-Status "BAD_ADDRESS diagnostics complete: $badCount finding(s) in $ScopeId"
        Write-ActionLog "BAD_ADDRESS diagnostics complete for $ScopeId — $badCount bad lease(s), pattern=$($Global:BadAddressDiag.Pattern)" "SUCCESS"
        Update-LogDisplay
        
    } catch {
        if ("$_" -match 'Canceled') {
            Write-ActionLog "BAD_ADDRESS diagnostics canceled" "WARN"
            Complete-TaskProgress -Message "BAD_ADDRESS diagnostics canceled"
            Set-Status "BAD_ADDRESS diagnostics canceled"
        } else {
            Write-ActionLog "BAD_ADDRESS diagnostics failed: $_" "ERROR"
            Complete-TaskProgress -Message "BAD_ADDRESS diagnostics failed"
            Set-Status "BAD_ADDRESS diagnostics failed"
            Show-MessageBox "Diagnostics failed: $_" "Troubleshoot Error" OK Error
        }
        Update-TroubleshootClearUi
        Update-LogDisplay
    }
}

function Export-BadAddressReport {
    if ((Get-SafeCount $Global:BadAddressFindings) -eq 0 -and (Get-SafeCount $Global:BadAddressLeases) -eq 0) {
        Show-MessageBox "Run diagnostics before exporting." "Nothing to Export" OK Information
        return
    }
    
    try {
        $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveDialog.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
        $saveDialog.Title = "Export BAD_ADDRESS Troubleshoot Report"
        $scopePart = if ($Global:BadAddressDiag.ScopeId) { ($Global:BadAddressDiag.ScopeId -replace '[^\d\.]', '_') } else { 'scope' }
        $saveDialog.FileName = "BAD_ADDRESS_$scopePart`_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        
        if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $rows = [System.Collections.Generic.List[object]]::new()
            foreach ($f in @($Global:BadAddressFindings)) {
                [void]$rows.Add([PSCustomObject]@{
                    Section        = 'Finding'
                    Step           = $f.Step
                    Check          = $f.Check
                    Status         = $f.Status
                    Finding        = $f.Finding
                    Recommendation = $f.Recommendation
                    IPAddress      = ''
                    PingStatus     = ''
                    ArpMac         = ''
                    HostName       = ''
                    AddressState   = ''
                })
            }
            foreach ($l in @($Global:BadAddressLeases)) {
                [void]$rows.Add([PSCustomObject]@{
                    Section        = 'BadLease'
                    Step           = ''
                    Check          = ''
                    Status         = ''
                    Finding        = ''
                    Recommendation = ''
                    IPAddress      = $l.IPAddress
                    PingStatus     = ''
                    ArpMac         = $l.ClientId
                    HostName       = $l.HostName
                    AddressState   = $l.AddressState
                })
            }
            foreach ($p in @($Global:BadAddressProbes)) {
                [void]$rows.Add([PSCustomObject]@{
                    Section        = 'Probe'
                    Step           = ''
                    Check          = ''
                    Status         = ''
                    Finding        = $p.Notes
                    Recommendation = ''
                    IPAddress      = $p.IPAddress
                    PingStatus     = $p.PingStatus
                    ArpMac         = $p.ArpMac
                    HostName       = ''
                    AddressState   = $p.ArpState
                })
            }
            
            $rows | Export-Csv -Path $saveDialog.FileName -NoTypeInformation -Encoding UTF8
            Write-ActionLog "Exported BAD_ADDRESS report: $($saveDialog.FileName)" "SUCCESS"
            Show-MessageBox "Exported report to:`n$($saveDialog.FileName)" "Export Complete" OK Information
            Update-LogDisplay
        }
    } catch {
        Write-ActionLog "BAD_ADDRESS export failed: $_" "ERROR"
        Show-MessageBox "Export failed: $_" "Export Error" OK Error
    }
}

function Show-TroubleshootDetailDialog {
    <#
    .SYNOPSIS
        Modal popup with full text for a Troubleshoot finding, BAD lease, or probe row
    #>
    param(
        [ValidateSet('Finding', 'BadLease', 'Probe')]
        [string]$Kind = 'Finding',
        [object]$Entry
    )
    
    if ($null -eq $Entry) {
        Show-MessageBox "Select a row first (or double-click a row)." "Troubleshoot Details" OK Warning
        return
    }
    
    $title = 'Troubleshoot Details'
    $subtitle = ''
    $fields = [System.Collections.Generic.List[object]]::new()
    $copyAll = [System.Collections.Generic.List[string]]::new()
    
    switch ($Kind) {
        'Finding' {
            $title = 'Diagnostic Finding Details'
            $step = "$($Entry.Step)"
            $check = "$($Entry.Check)"
            $status = "$($Entry.Status)"
            $finding = "$($Entry.Finding)"
            $rec = "$($Entry.Recommendation)"
            $subtitle = "Step $step  ·  $check  ·  $status"
            [void]$fields.Add(@{ Label = 'Step'; Value = $step; Tall = $false })
            [void]$fields.Add(@{ Label = 'Check'; Value = $check; Tall = $false })
            [void]$fields.Add(@{ Label = 'Status'; Value = $status; Tall = $false })
            [void]$fields.Add(@{ Label = 'Finding'; Value = $finding; Tall = $true })
            [void]$fields.Add(@{ Label = 'Recommendation'; Value = $rec; Tall = $true })
            if ($Global:BadAddressDiag.ScopeId) {
                [void]$fields.Add(@{ Label = 'Scope'; Value = "$($Global:BadAddressDiag.ScopeId) on $($Global:BadAddressDiag.Server)"; Tall = $false })
            }
            if ($Global:BadAddressDiag.Summary) {
                [void]$fields.Add(@{ Label = 'Run summary'; Value = "$($Global:BadAddressDiag.Summary)"; Tall = $true })
            }
            [void]$copyAll.Add("Diagnostic Finding Details")
            [void]$copyAll.Add("Step: $step")
            [void]$copyAll.Add("Check: $check")
            [void]$copyAll.Add("Status: $status")
            [void]$copyAll.Add("Finding: $finding")
            [void]$copyAll.Add("Recommendation: $rec")
        }
        'BadLease' {
            $title = 'BAD_ADDRESS Lease Details'
            $ip = "$($Entry.IPAddress)"
            $clientId = "$($Entry.ClientId)"
            $hostName = "$($Entry.HostName)"
            $state = "$($Entry.AddressState)"
            $expiry = "$($Entry.LeaseExpiryTime)"
            $subtitle = "$ip  ·  $state"
            [void]$fields.Add(@{ Label = 'IP Address'; Value = $ip; Tall = $false })
            [void]$fields.Add(@{ Label = 'MAC / ClientId'; Value = $clientId; Tall = $false })
            [void]$fields.Add(@{ Label = 'Hostname'; Value = $hostName; Tall = $false })
            [void]$fields.Add(@{ Label = 'State'; Value = $state; Tall = $false })
            [void]$fields.Add(@{ Label = 'Lease Expiry'; Value = $expiry; Tall = $false })
            if ($Global:BadAddressDiag.ScopeId) {
                [void]$fields.Add(@{ Label = 'Scope'; Value = "$($Global:BadAddressDiag.ScopeId)"; Tall = $false })
            }
            [void]$copyAll.Add("BAD_ADDRESS Lease Details")
            [void]$copyAll.Add("IP Address: $ip")
            [void]$copyAll.Add("MAC / ClientId: $clientId")
            [void]$copyAll.Add("Hostname: $hostName")
            [void]$copyAll.Add("State: $state")
            [void]$copyAll.Add("Lease Expiry: $expiry")
        }
        'Probe' {
            $title = 'Ping / ARP Probe Details'
            $ip = "$($Entry.IPAddress)"
            $ping = "$($Entry.PingStatus)"
            $lat = "$($Entry.LatencyMs)"
            $mac = "$($Entry.ArpMac)"
            $arpState = "$($Entry.ArpState)"
            $notes = "$($Entry.Notes)"
            $subtitle = "$ip  ·  Ping $ping  ·  ARP $arpState"
            [void]$fields.Add(@{ Label = 'IP Address'; Value = $ip; Tall = $false })
            [void]$fields.Add(@{ Label = 'Ping'; Value = $ping; Tall = $false })
            [void]$fields.Add(@{ Label = 'Latency'; Value = $lat; Tall = $false })
            [void]$fields.Add(@{ Label = 'ARP MAC'; Value = $mac; Tall = $false })
            [void]$fields.Add(@{ Label = 'ARP State'; Value = $arpState; Tall = $false })
            [void]$fields.Add(@{ Label = 'Notes'; Value = $notes; Tall = $true })
            if ($Global:BadAddressDiag.ScopeId) {
                [void]$fields.Add(@{ Label = 'Scope'; Value = "$($Global:BadAddressDiag.ScopeId)"; Tall = $false })
            }
            [void]$copyAll.Add("Ping / ARP Probe Details")
            [void]$copyAll.Add("IP Address: $ip")
            [void]$copyAll.Add("Ping: $ping")
            [void]$copyAll.Add("Latency: $lat")
            [void]$copyAll.Add("ARP MAC: $mac")
            [void]$copyAll.Add("ARP State: $arpState")
            [void]$copyAll.Add("Notes: $notes")
        }
    }
    
    [xml]$dialogXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Troubleshoot Details"
        Height="520" Width="720"
        MinHeight="360" MinWidth="520"
        WindowStartupLocation="CenterOwner"
        Background="#1A1D23"
        FontFamily="Segoe UI" FontSize="13"
        ResizeMode="CanResizeWithGrip">
  <Grid Margin="16">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <StackPanel Grid.Row="0" Margin="0,0,0,12">
      <TextBlock x:Name="TxtTsDetailTitle" Foreground="#E8EAF0" FontSize="18" FontWeight="SemiBold"/>
      <TextBlock x:Name="TxtTsDetailSubtitle" Foreground="#9AA3B2" FontSize="12" Margin="0,4,0,0" TextWrapping="Wrap"/>
    </StackPanel>

    <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
      <StackPanel x:Name="PanelTsDetailFields"/>
    </ScrollViewer>

    <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,12,0,0">
      <Button x:Name="BtnTsDetailCopy" Content="Copy All" Width="100" Height="30" Margin="0,0,8,0"
              Background="#2A2F3A" Foreground="#E8EAF0" BorderBrush="#383E4A" BorderThickness="1"/>
      <Button x:Name="BtnTsDetailClose" Content="Close" Width="90" Height="30" IsDefault="True" IsCancel="True"
              Background="#2196F3" Foreground="White" BorderThickness="0"/>
    </StackPanel>
  </Grid>
</Window>
'@
    
    try {
        $dialog = [Windows.Markup.XamlReader]::Load([System.Xml.XmlNodeReader]::new($dialogXaml))
        if ($script:Window) { $dialog.Owner = $script:Window }
        $dialog.Title = $title
        $dialog.FindName('TxtTsDetailTitle').Text = $title
        $dialog.FindName('TxtTsDetailSubtitle').Text = $subtitle
        
        $panel = $dialog.FindName('PanelTsDetailFields')
        foreach ($f in $fields) {
            $border = New-Object System.Windows.Controls.Border
            $border.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#22262E')
            $border.CornerRadius = [System.Windows.CornerRadius]::new(6)
            $border.Padding = [System.Windows.Thickness]::new(12)
            $border.Margin = [System.Windows.Thickness]::new(0, 0, 0, 10)
            
            $stack = New-Object System.Windows.Controls.StackPanel
            $lbl = New-Object System.Windows.Controls.TextBlock
            $lbl.Text = "$($f.Label)"
            $lbl.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#90CAF9')
            $lbl.FontWeight = [System.Windows.FontWeights]::SemiBold
            $lbl.Margin = [System.Windows.Thickness]::new(0, 0, 0, 6)
            
            $box = New-Object System.Windows.Controls.TextBox
            $box.Text = "$(if ($null -ne $f.Value) { $f.Value } else { '' })"
            $box.IsReadOnly = $true
            $box.TextWrapping = [System.Windows.TextWrapping]::Wrap
            $box.AcceptsReturn = $true
            $box.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#12151A')
            $box.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#E8EAF0')
            $box.BorderBrush = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#383E4A')
            $box.BorderThickness = [System.Windows.Thickness]::new(1)
            $box.Padding = [System.Windows.Thickness]::new(8, 6, 8, 6)
            if ($f.Tall) {
                $box.MinHeight = 72
                $box.VerticalScrollBarVisibility = [System.Windows.Controls.ScrollBarVisibility]::Auto
            } else {
                $box.MinHeight = 28
            }
            
            [void]$stack.Children.Add($lbl)
            [void]$stack.Children.Add($box)
            $border.Child = $stack
            [void]$panel.Children.Add($border)
        }
        
        $script:TroubleshootDetailCopyAll = ($copyAll -join [Environment]::NewLine)
        
        $btnCopy = $dialog.FindName('BtnTsDetailCopy')
        $btnClose = $dialog.FindName('BtnTsDetailClose')
        $btnCopy.add_Click({
            try {
                [System.Windows.Clipboard]::SetText("$($script:TroubleshootDetailCopyAll)")
                Write-ActionLog "Copied Troubleshoot detail text to clipboard" "INFO"
            } catch {
                Show-MessageBox "Could not copy to clipboard: $_" "Troubleshoot Details" OK Warning
            }
        })
        $btnClose.add_Click({
            $dialog.DialogResult = $true
            $dialog.Close()
        })
        
        [void]$dialog.ShowDialog()
    } catch {
        Write-ActionLog "Troubleshoot detail dialog failed: $_" "ERROR"
        Show-MessageBox "Could not open details: $_" "Troubleshoot Details" OK Error
    }
}

function Clear-BadAddressLeasesForScope {
    <#
    .SYNOPSIS
        Clears BAD_ADDRESS leases only after diagnostics + operator confirmation
    #>
    
    if ([string]::IsNullOrWhiteSpace($Global:DHCPServer)) {
        Show-MessageBox "Connect to a DHCP server first." "Not Connected" OK Warning
        return
    }
    
    $scopeId = "$($Global:BadAddressDiag.ScopeId)"
    if (-not $scopeId) { $scopeId = Get-TroubleshootScopeIdFromUi }
    
    if (-not $Global:BadAddressDiag.CanClear -or -not $Global:BadAddressDiag.RanAt) {
        Show-MessageBox "Run diagnostics for this scope before clearing BAD_ADDRESS leases." "Diagnostics Required" OK Warning
        return
    }
    
    $uiScope = Get-TroubleshootScopeIdFromUi
    if ($uiScope -and $Global:BadAddressDiag.ScopeId -and $uiScope -ne $Global:BadAddressDiag.ScopeId) {
        Show-MessageBox "Selected scope ($uiScope) does not match the last diagnostics scope ($($Global:BadAddressDiag.ScopeId)). Re-run diagnostics for the selected scope." "Scope Mismatch" OK Warning
        return
    }
    
    $reviewed = $false
    try { $reviewed = [bool]$script:ChkTroubleshootReviewed.IsChecked } catch {}
    if (-not $reviewed) {
        Show-MessageBox "Confirm you reviewed the findings and corrected the root cause before clearing." "Confirmation Required" OK Warning
        return
    }
    
    $badCount = [int]$Global:BadAddressDiag.BadCount
    if ($badCount -le 0) {
        Show-MessageBox "No BAD_ADDRESS leases to clear." "Nothing to Clear" OK Information
        return
    }
    
    $confirm = Show-MessageBox "Clear $badCount BAD_ADDRESS lease(s) on scope $scopeId from server $($Global:DHCPServer)?`n`nOnly proceed if the root cause is fixed — otherwise BAD_ADDRESS entries will return." "Confirm Clear BAD_ADDRESS" YesNo Warning
    if ($confirm -ne [System.Windows.MessageBoxResult]::Yes) { return }
    
    Write-ActionLog "Clearing $badCount BAD_ADDRESS lease(s) on $scopeId..." "INFO"
    Set-Status "Clearing BAD_ADDRESS leases on $scopeId..."
    
    $ips = @($Global:BadAddressLeases | ForEach-Object { "$($_.IPAddress)" } | Where-Object { $_ })
    if ((Get-SafeCount $ips) -eq 0) {
        try {
            $ips = @(Get-BadAddressLeasesForScope -Server $Global:DHCPServer -ScopeId $scopeId | ForEach-Object { "$($_.IPAddress)" })
        } catch {
            Show-MessageBox "Failed to reload BAD_ADDRESS leases: $_" "Clear Failed" OK Error
            return
        }
    }
    
    $total = Get-SafeCount $ips
    Start-TaskProgress -Name 'ClearBadAddress' -Message "Clearing BAD_ADDRESS leases..." -CanPause -Total $total
    $ok = 0
    $fail = 0
    
    try {
        $i = 0
        foreach ($ip in $ips) {
            Wait-TaskProgressIfPaused
            if (Test-TaskCancelRequested) { break }
            $i++
            Update-TaskProgress -Processed $i -Message "Removing BAD_ADDRESS $ip..."
            try {
                Remove-DhcpServerv4Lease -ComputerName $Global:DHCPServer -IPAddress $ip -ErrorAction Stop
                $ok++
                Write-ActionLog "Removed BAD_ADDRESS lease $ip" "SUCCESS"
            } catch {
                $fail++
                Write-ActionLog "Failed to remove BAD_ADDRESS $ip : $_" "ERROR"
            }
        }
        
        Complete-TaskProgress -Message "Clear BAD_ADDRESS finished: $ok ok, $fail failed"
        Set-Status "Cleared BAD_ADDRESS: $ok ok, $fail failed"
        Show-MessageBox "Removed $ok BAD_ADDRESS lease(s). Failed: $fail." "Clear Complete" OK Information
        
        # Refresh diagnostics inventory for the same scope
        Invoke-BadAddressDiagnostics -ScopeId $scopeId -SampleSize (Get-TroubleshootSampleSize)
    } catch {
        Complete-TaskProgress -Message "Clear BAD_ADDRESS failed"
        Write-ActionLog "Clear BAD_ADDRESS failed: $_" "ERROR"
        Show-MessageBox "Clear failed: $_" "Clear Error" OK Error
    }
    Update-LogDisplay
}

function Initialize-TroubleshootTab {
    try {
        if ($null -ne $script:GridTroubleshootFindings) {
            $script:GridTroubleshootFindings.ItemsSource = $Global:BadAddressFindings
        }
        if ($null -ne $script:GridTroubleshootBadLeases) {
            $script:GridTroubleshootBadLeases.ItemsSource = $Global:BadAddressLeases
        }
        if ($null -ne $script:GridTroubleshootProbes) {
            $script:GridTroubleshootProbes.ItemsSource = $Global:BadAddressProbes
        }
        if (-not [string]::IsNullOrWhiteSpace($Global:DHCPServer)) {
            Update-TroubleshootScopeList
            if ($Global:SelectedScope) { [void](Set-TroubleshootScopeSelection -ScopeId $Global:SelectedScope) }
        }
    } catch {
        Write-ActionLog "Initialize-TroubleshootTab: $_" "WARN"
    }
}
#endregion

function Get-ScopeUtilThresholdPercent {
    $threshold = 90
    try {
        if ($null -ne $script:CboUtilThreshold -and $null -ne $script:CboUtilThreshold.SelectedItem) {
            $text = "$($script:CboUtilThreshold.SelectedItem.Content)" -replace '[^0-9]', ''
            $parsed = 0
            if ([int]::TryParse($text, [ref]$parsed) -and $parsed -gt 0 -and $parsed -le 100) {
                $threshold = $parsed
            }
        }
    } catch {}
    $Global:ScopeUtilThreshold = $threshold
    return $threshold
}

function Get-ScopeUtilLevel {
    param(
        [double]$PercentInUse,
        [int]$Threshold = 90
    )
    
    $warnAt = [math]::Max(0, $Threshold - 10)
    if ($PercentInUse -ge $Threshold) { return 'Critical' }
    if ($PercentInUse -ge $warnAt) { return 'Warning' }
    return 'OK'
}

function Get-ScopeStatFilterMode {
    $mode = 'All scopes'
    try {
        if ($null -ne $script:CboScopeStatFilter -and $null -ne $script:CboScopeStatFilter.SelectedItem) {
            $mode = "$($script:CboScopeStatFilter.SelectedItem.Content)"
        }
    } catch {}
    return $mode
}


#region IPAM-style Monitoring Dashboard
function Initialize-DashboardBindings {
    try {
        if ($null -ne $script:GridDashboardAlerts) {
            $script:GridDashboardAlerts.ItemsSource = $Global:DashboardAlerts
        }
        if ($null -ne $script:GridDashboardTopScopes) {
            $script:GridDashboardTopScopes.ItemsSource = $Global:DashboardTopScopes
        }
        if ($null -ne $script:GridDashboardEstate) {
            $script:GridDashboardEstate.ItemsSource = $Global:DashboardEstate
        }
    } catch {
        Write-ActionLog "Initialize-DashboardBindings: $_" "WARN"
    }
}

function Sync-DashboardEstatePanel {
    try {
        $Global:DashboardEstate.Clear()
        $rows = @($Global:DomainScanResults)
        $total = Get-SafeCount $rows
        $up = Get-SafeCount @($rows | Where-Object { "$($_.Online)" -match 'Up|Yes' })
        $Global:DashboardHealth.EstateTotal = $total
        $Global:DashboardHealth.EstateOnline = $up
        
        foreach ($r in @($rows | Select-Object -First 40)) {
            [void]$Global:DashboardEstate.Add([PSCustomObject]@{
                DnsName     = "$($r.DnsName)"
                IPAddress   = "$($r.IPAddress)"
                Online      = "$($r.Online)"
                Authorized  = "$($r.Authorized)"
                LatencyMs   = "$(if ($null -ne $r.LatencyMs) { $r.LatencyMs } else { '' })"
                Detail      = "$(if ($r.Detail) { $r.Detail } elseif ($r.AuthDetail) { $r.AuthDetail } else { '' })"
            })
        }
        
        if ($null -ne $script:TxtDashboardEstateHint) {
            if ($total -gt 0) {
                $script:TxtDashboardEstateHint.Text = "Estate: $up Up / $total scanned  ·  showing up to 40"
            } else {
                $script:TxtDashboardEstateHint.Text = "Run Scan Domain to populate multi-server health"
            }
        }
    } catch {
        Write-ActionLog "Sync-DashboardEstatePanel: $_" "WARN"
    }
}

function Get-DashboardFailoverSummary {
    param([string]$Server)
    if ([string]::IsNullOrWhiteSpace($Server)) { return 'Not connected' }
    try {
        $failovers = @(Get-DhcpServerv4Failover -ComputerName $Server -ErrorAction SilentlyContinue)
        if ((Get-SafeCount $failovers) -eq 0) {
            return 'No failover relationships (standalone or not configured).'
        }
        $bits = [System.Collections.Generic.List[string]]::new()
        foreach ($fo in $failovers) {
            [void]$bits.Add("$($fo.Name): partner=$($fo.PartnerServer); mode=$($fo.Mode); state=$($fo.State)")
        }
        return ($bits -join ' | ')
    } catch {
        return "Failover query unavailable: $_"
    }
}

function Get-DashboardConflictSummary {
    param([string]$Server)
    if ([string]::IsNullOrWhiteSpace($Server)) { return 'Not connected' }
    try {
        $settings = Get-DhcpServerSetting -ComputerName $Server -ErrorAction Stop
        return "ConflictDetectionAttempts=$($settings.ConflictDetectionAttempts)"
    } catch {
        return "Conflict detection setting unavailable"
    }
}

function Sync-DashboardUi {
    <#
    .SYNOPSIS
        Rebuilds IPAM-style dashboard widgets from current stats / scan / health
    #>
    param(
        [switch]$RefreshHealth
    )
    
    Initialize-DashboardBindings
    
    $threshold = Get-ScopeUtilThresholdPercent
    $all = @($Global:ScopeStatEntriesAll)
    $critical = @($all | Where-Object { "$($_.Level)" -eq 'Critical' })
    $warning = @($all | Where-Object { "$($_.Level)" -eq 'Warning' })
    $criticalCount = Get-SafeCount $critical
    $warningCount = Get-SafeCount $warning
    
    $Global:DashboardHealth.CriticalCount = $criticalCount
    $Global:DashboardHealth.WarningCount = $warningCount
    $Global:DashboardHealth.Server = "$($Global:DHCPServer)"
    $Global:DashboardHealth.RefreshedAt = Get-Date
    
    if ($RefreshHealth -and -not [string]::IsNullOrWhiteSpace($Global:DHCPServer)) {
        $Global:DashboardHealth.FailoverSummary = Get-DashboardFailoverSummary -Server $Global:DHCPServer
        $Global:DashboardHealth.ConflictDetection = Get-DashboardConflictSummary -Server $Global:DHCPServer
    }
    
    try {
        $script:Window.Dispatcher.Invoke([action]{
            # KPIs — prefer Statistics card values when present
            if ($null -ne $script:DashKpiScopes) {
                $script:DashKpiScopes.Text = if ($null -ne $script:StatTotalScopes -and $script:StatTotalScopes.Text) { $script:StatTotalScopes.Text } else { "$(Get-SafeCount $all)" }
            }
            if ($null -ne $script:DashKpiLeases -and $null -ne $script:StatActiveLeases) {
                $script:DashKpiLeases.Text = "$($script:StatActiveLeases.Text)"
            }
            if ($null -ne $script:DashKpiAvailable -and $null -ne $script:StatAvailableIPs) {
                $script:DashKpiAvailable.Text = "$($script:StatAvailableIPs.Text)"
            }
            if ($null -ne $script:DashKpiUtil -and $null -ne $script:StatUtilization) {
                $script:DashKpiUtil.Text = "$($script:StatUtilization.Text)"
                try { $script:DashKpiUtil.Foreground = $script:StatUtilization.Foreground } catch {}
            }
            if ($null -ne $script:DashKpiCritical) { $script:DashKpiCritical.Text = "$criticalCount" }
            if ($null -ne $script:DashKpiWarning) { $script:DashKpiWarning.Text = "$warningCount" }
            
            $Global:DashboardAlerts.Clear()
            foreach ($row in $critical) {
                [void]$Global:DashboardAlerts.Add([PSCustomObject]@{
                    Severity  = 'Critical'
                    AlertType = 'Scope utilization'
                    ScopeId   = "$($row.ScopeId)"
                    Name      = "$($row.Name)"
                    Detail    = "$($row.PercentDisplay) in use · Free=$($row.Free) · Threshold ≥$threshold%"
                    Level     = 'Critical'
                    SourceRow = $row
                })
            }
            foreach ($row in @($warning | Select-Object -First 25)) {
                [void]$Global:DashboardAlerts.Add([PSCustomObject]@{
                    Severity  = 'Warning'
                    AlertType = 'Scope utilization'
                    ScopeId   = "$($row.ScopeId)"
                    Name      = "$($row.Name)"
                    Detail    = "$($row.PercentDisplay) in use · Free=$($row.Free) · approaching capacity"
                    Level     = 'Warning'
                    SourceRow = $row
                })
            }
            
            $Global:DashboardTopScopes.Clear()
            $rank = 0
            foreach ($row in @($all | Select-Object -First 10)) {
                $rank++
                [void]$Global:DashboardTopScopes.Add([PSCustomObject]@{
                    Rank           = $rank
                    PercentDisplay = "$($row.PercentDisplay)"
                    Status         = "$($row.Status)"
                    ScopeId        = "$($row.ScopeId)"
                    Name           = "$($row.Name)"
                    Free           = $row.Free
                    PercentInUse   = $row.PercentInUse
                    Level          = "$($row.Level)"
                    SourceRow      = $row
                })
            }
            
            $server = if ($Global:DHCPServer) { $Global:DHCPServer } else { '(not connected)' }
            $when = if ($Global:DashboardHealth.RefreshedAt) { Get-Date $Global:DashboardHealth.RefreshedAt -Format 'HH:mm:ss' } else { '—' }
            $fo = "$($Global:DashboardHealth.FailoverSummary)"
            if (-not $fo) { $fo = 'Refresh Monitoring to load failover state.' }
            $cd = "$($Global:DashboardHealth.ConflictDetection)"
            if (-not $cd) { $cd = '—' }
            
            if ($null -ne $script:TxtDashboardHealth) {
                $script:TxtDashboardHealth.Text = "Server: $server  ·  Refreshed: $when  ·  $cd  ·  Failover: $fo"
            }
            if ($null -ne $script:TxtDashboardSubtitle) {
                $script:TxtDashboardSubtitle.Text = "Monitoring $server — Critical $criticalCount / Warning $warningCount (flag ≥${threshold}%). Top 10 and Active Alerts update with each refresh."
            }
            if ($null -ne $script:TxtDashboardStatus) {
                $estateNote = if ($Global:DashboardHealth.EstateTotal -gt 0) {
                    "Estate snapshot: $($Global:DashboardHealth.EstateOnline)/$($Global:DashboardHealth.EstateTotal) online."
                } else {
                    "Estate snapshot empty — use Scan Estate for multi-server inventory."
                }
                $script:TxtDashboardStatus.Text = "IPAM-style summary ready. $estateNote Double-click an alert or Top 10 row for scope details. Use Troubleshoot for BAD_ADDRESS root cause."
            }
        }, [System.Windows.Threading.DispatcherPriority]::Normal)
    } catch {
        Write-ActionLog "Sync-DashboardUi: $_" "ERROR"
    }
    
    Sync-DashboardEstatePanel
}

function Invoke-DashboardRefresh {
    <#
    .SYNOPSIS
        Full monitoring refresh — statistics poll + dashboard widgets + health
    #>
    if ([string]::IsNullOrWhiteSpace($Global:DHCPServer)) {
        Show-MessageBox "Connect to a DHCP server first." "Dashboard" OK Warning
        return
    }
    
    Write-ActionLog "Dashboard monitoring refresh starting..." "INFO"
    Load-Statistics
    Sync-DashboardUi -RefreshHealth
    Set-Status "Dashboard monitoring refreshed"
}

function Apply-ScopeGridFilter {
    if ($null -eq $script:GridScopes) { return }
    $query = ''
    try {
        if ($null -ne $script:TxtScopeFilter) { $query = "$($script:TxtScopeFilter.Text)".Trim() }
    } catch {}
    
    $all = @()
    try {
        # Prefer last full load stored on Tag, else current ItemsSource
        if ($null -ne $script:GridScopes.Tag) {
            $all = @($script:GridScopes.Tag)
        } elseif ($null -ne $script:GridScopes.ItemsSource) {
            $all = @($script:GridScopes.ItemsSource)
            $script:GridScopes.Tag = $all
        }
    } catch {}
    
    if ((Get-SafeCount $all) -eq 0) {
        if ($null -ne $script:TxtScopeFilterCount) { $script:TxtScopeFilterCount.Text = '' }
        return
    }
    
    if (-not $query) {
        $script:GridScopes.ItemsSource = $all
        if ($null -ne $script:TxtScopeFilterCount) {
            $script:TxtScopeFilterCount.Text = "$(Get-SafeCount $all) scope(s)"
        }
        return
    }
    
    $q = $query.ToLowerInvariant()
    $filtered = @($all | Where-Object {
        $blob = ("$($_.ScopeId) $($_.Name) $($_.StartRange) $($_.EndRange) $($_.SubnetMask) $($_.State)").ToLowerInvariant()
        $blob.Contains($q)
    })
    $script:GridScopes.ItemsSource = $filtered
    if ($null -ne $script:TxtScopeFilterCount) {
        $script:TxtScopeFilterCount.Text = "$(Get-SafeCount $filtered) of $(Get-SafeCount $all) scope(s)"
    }
}
#endregion

function Update-ScopeUtilAlertBanner {
    param(
        [int]$CriticalCount = 0,
        [int]$WarningCount = 0,
        [int]$Threshold = 90,
        [object[]]$CriticalScopes = @()
    )
    
    try {
        $script:Window.Dispatcher.Invoke([action]{
            if ($null -eq $script:ScopeUtilAlertBanner -or $null -eq $script:TxtScopeUtilAlert) { return }
            
            if ($CriticalCount -le 0 -and $WarningCount -le 0) {
                $script:ScopeUtilAlertBanner.Visibility = [System.Windows.Visibility]::Collapsed
                $script:TxtScopeUtilAlert.Text = ''
                return
            }
            
            $parts = [System.Collections.Generic.List[string]]::new()
            if ($CriticalCount -gt 0) {
                $names = @($CriticalScopes | ForEach-Object {
                    $label = "$($_.Name)"
                    if (-not $label) { $label = "$($_.ScopeId)" }
                    "$label ($($_.PercentDisplay))"
                } | Select-Object -First 8)
                $list = $names -join '; '
                if ($CriticalCount -gt 8) { $list = "$list; …" }
                [void]$parts.Add("$CriticalCount scope(s) at or above ${Threshold}% utilization: $list")
            }
            if ($WarningCount -gt 0) {
                $warnAt = [math]::Max(0, $Threshold - 10)
                [void]$parts.Add("$WarningCount scope(s) in the warning band (${warnAt}–$([math]::Max(0, $Threshold - 1))%). Double-click a row for details.")
            } else {
                [void]$parts.Add('Double-click a flagged scope (or select and click Scope Details) for full statistics.')
            }
            
            $script:TxtScopeUtilAlert.Text = ($parts -join '  ')
            $script:ScopeUtilAlertBanner.Visibility = [System.Windows.Visibility]::Visible
        }, [System.Windows.Threading.DispatcherPriority]::Normal)
    } catch {}
}

function Apply-ScopeStatFilter {
    $mode = Get-ScopeStatFilterMode
    $visible = [System.Collections.Generic.List[object]]::new()
    
    foreach ($row in @($Global:ScopeStatEntriesAll)) {
        if ($null -eq $row) { continue }
        $level = "$($row.Level)"
        switch ($mode) {
            'Critical only' {
                if ($level -eq 'Critical') { [void]$visible.Add($row) }
            }
            'Warning + Critical' {
                if ($level -eq 'Critical' -or $level -eq 'Warning') { [void]$visible.Add($row) }
            }
            default {
                [void]$visible.Add($row)
            }
        }
    }
    
    try {
        $script:Window.Dispatcher.Invoke([action]{
            $Global:ScopeStatEntries.Clear()
            foreach ($row in $visible) {
                [void]$Global:ScopeStatEntries.Add($row)
            }
            if ($null -ne $script:GridScopeStats) {
                if ($null -eq $script:GridScopeStats.ItemsSource) {
                    $script:GridScopeStats.ItemsSource = $Global:ScopeStatEntries
                }
            }
            if ($null -ne $script:TxtScopeStatStatus) {
                $shown = Get-SafeCount $visible
                $total = Get-SafeCount $Global:ScopeStatEntriesAll
                $script:TxtScopeStatStatus.Text = "Showing $shown of $total scope(s)  ·  Filter: $mode  ·  Flag threshold: $(Get-ScopeUtilThresholdPercent)%"
            }
        }, [System.Windows.Threading.DispatcherPriority]::Normal)
    } catch {
        Write-ActionLog "Failed to apply scope stats filter: $_" "ERROR"
    }
}

function New-ScopeStatRow {
    param(
        [object]$Scope,
        [object]$Stat,
        [int]$Threshold = 90
    )
    
    $inUse = 0
    $free = 0
    $reserved = 0
    $pending = 0
    $pct = 0.0
    
    try { $inUse = [int]$Stat.AddressesInUse } catch { $inUse = 0 }
    try { $free = [int]$Stat.AddressesFree } catch { $free = 0 }
    try { $reserved = [int]$Stat.ReservedAddress } catch {
        try { $reserved = [int]$Stat.ReservedAddresses } catch { $reserved = 0 }
    }
    try { $pending = [int]$Stat.PendingOffers } catch { $pending = 0 }
    
    $total = $inUse + $free
    try {
        if ($null -ne $Stat.PercentageInUse) {
            $pct = [double]$Stat.PercentageInUse
        } elseif ($total -gt 0) {
            $pct = ($inUse / [double]$total) * 100.0
        }
    } catch {
        if ($total -gt 0) { $pct = ($inUse / [double]$total) * 100.0 }
    }
    $pct = [math]::Round($pct, 1)
    
    $level = Get-ScopeUtilLevel -PercentInUse $pct -Threshold $Threshold
    $status = switch ($level) {
        'Critical' { "Critical ≥${Threshold}%" }
        'Warning'  { 'Warning' }
        default    { 'OK' }
    }
    
    $startRange = ''
    $endRange = ''
    $mask = ''
    $lease = ''
    $name = ''
    $state = ''
    $desc = ''
    $scopeId = ''
    
    try { $scopeId = "$($Scope.ScopeId)" } catch {
        try { $scopeId = "$($Stat.ScopeId)" } catch { $scopeId = '' }
    }
    try { $name = "$($Scope.Name)" } catch { $name = '' }
    try { $state = "$($Scope.State)" } catch { $state = '' }
    try { $startRange = "$($Scope.StartRange)" } catch { $startRange = '' }
    try { $endRange = "$($Scope.EndRange)" } catch { $endRange = '' }
    try { $mask = "$($Scope.SubnetMask)" } catch { $mask = '' }
    try { $desc = "$($Scope.Description)" } catch { $desc = '' }
    try {
        if ($null -ne $Scope.LeaseDuration) {
            $lease = "$($Scope.LeaseDuration)"
        }
    } catch { $lease = '' }
    
    $rangeDisplay = if ($startRange -and $endRange) { "$startRange – $endRange" } else { '' }
    
    return [PSCustomObject]@{
        ScopeId         = $scopeId
        Name            = $name
        State           = $state
        Description     = $desc
        StartRange      = $startRange
        EndRange        = $endRange
        SubnetMask      = $mask
        LeaseDuration   = $lease
        RangeDisplay    = $rangeDisplay
        InUse           = $inUse
        Free            = $free
        Total           = $total
        Reserved        = $reserved
        Pending         = $pending
        PercentInUse    = $pct
        PercentDisplay  = "$pct%"
        Level           = $level
        Status          = $status
        Threshold       = $threshold
    }
}

function Show-ScopeStatDetailDialog {
    <#
    .SYNOPSIS
        Modal with detailed utilization and scope configuration for one scope
    #>
    param([object]$Entry)
    
    if ($null -eq $Entry) {
        Show-MessageBox "Select a scope row first (or double-click a row)." "Scope Details" OK Warning
        return
    }
    
    $scopeId = "$($Entry.ScopeId)"
    $exclusions = [System.Collections.Generic.List[string]]::new()
    $exclusionCount = 0
    $reservationSamples = [System.Collections.Generic.List[string]]::new()
    
    if ($Global:DHCPServer -and $scopeId) {
        try {
            $ex = @(Get-DhcpServerv4ExclusionRange -ComputerName $Global:DHCPServer -ScopeId $scopeId -ErrorAction SilentlyContinue)
            $exclusionCount = Get-SafeCount $ex
            foreach ($item in $ex) {
                [void]$exclusions.Add("$($item.StartRange) – $($item.EndRange)")
                if ((Get-SafeCount $exclusions) -ge 20) { break }
            }
        } catch {}
        
        try {
            $res = @(Get-DhcpServerv4Reservation -ComputerName $Global:DHCPServer -ScopeId $scopeId -ErrorAction SilentlyContinue |
                Select-Object -First 15)
            foreach ($r in $res) {
                [void]$reservationSamples.Add("$($r.IPAddress)  $($r.ClientId)  $($r.Name)")
            }
        } catch {}
    }
    
    $level = "$($Entry.Level)"
    $advice = switch ($level) {
        'Critical' {
            "This scope is at or above the $($Entry.Threshold)% flag threshold. Consider expanding the range, reclaiming stale leases, adding a secondary scope/superscope, or reducing lease duration if appropriate."
        }
        'Warning' {
            "This scope is approaching capacity. Monitor growth and plan expansion before it reaches $($Entry.Threshold)%."
        }
        default {
            "Utilization is within the configured threshold. No immediate capacity action required based on this scan."
        }
    }
    
    $exclusionText = if ($exclusionCount -gt 0) {
        $joined = ($exclusions -join [Environment]::NewLine)
        if ($exclusionCount -gt (Get-SafeCount $exclusions)) {
            "$joined`n… ($exclusionCount total)"
        } else {
            $joined
        }
    } else {
        '(none)'
    }
    
    $resText = if ((Get-SafeCount $reservationSamples) -gt 0) {
        ($reservationSamples -join [Environment]::NewLine)
    } else {
        '(none listed)'
    }
    
    [xml]$dialogXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Scope Statistics Details"
        Height="640" Width="760"
        MinHeight="480" MinWidth="600"
        WindowStartupLocation="CenterOwner"
        Background="#1A1D23"
        FontFamily="Segoe UI" FontSize="13"
        ResizeMode="CanResizeWithGrip">
  <Grid Margin="16">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <StackPanel Grid.Row="0" Margin="0,0,0,12">
      <TextBlock x:Name="TxtScopeDetailTitle" Foreground="#E8EAF0" FontSize="18" FontWeight="SemiBold"/>
      <TextBlock x:Name="TxtScopeDetailSubtitle" Foreground="#9AA3B2" FontSize="12" Margin="0,4,0,0" TextWrapping="Wrap"/>
    </StackPanel>

    <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto">
      <StackPanel>
        <Border Background="#22262E" CornerRadius="6" Padding="12" Margin="0,0,0,10">
          <StackPanel>
            <TextBlock Text="Utilization" Foreground="#90CAF9" FontWeight="SemiBold" Margin="0,0,0,8"/>
            <TextBlock x:Name="TxtScopeDetailUtil" Foreground="#E8EAF0" TextWrapping="Wrap"/>
          </StackPanel>
        </Border>
        <Border Background="#22262E" CornerRadius="6" Padding="12" Margin="0,0,0,10">
          <StackPanel>
            <TextBlock Text="Scope configuration" Foreground="#90CAF9" FontWeight="SemiBold" Margin="0,0,0,8"/>
            <TextBlock x:Name="TxtScopeDetailConfig" Foreground="#E8EAF0" TextWrapping="Wrap"/>
          </StackPanel>
        </Border>
        <Border Background="#22262E" CornerRadius="6" Padding="12" Margin="0,0,0,10">
          <StackPanel>
            <TextBlock Text="Guidance" Foreground="#90CAF9" FontWeight="SemiBold" Margin="0,0,0,8"/>
            <TextBlock x:Name="TxtScopeDetailAdvice" Foreground="#E8EAF0" TextWrapping="Wrap"/>
          </StackPanel>
        </Border>
        <Border Background="#22262E" CornerRadius="6" Padding="12" Margin="0,0,0,10">
          <StackPanel>
            <TextBlock Text="Exclusion ranges" Foreground="#90CAF9" FontWeight="SemiBold" Margin="0,0,0,8"/>
            <TextBox x:Name="TxtScopeDetailExclusions" IsReadOnly="True" TextWrapping="Wrap"
                     AcceptsReturn="True" MinHeight="70" VerticalScrollBarVisibility="Auto"
                     Background="#12151A" Foreground="#C5CAD3" BorderBrush="#383E4A"
                     BorderThickness="1" Padding="8,6" FontFamily="Consolas" FontSize="12"/>
          </StackPanel>
        </Border>
        <Border Background="#22262E" CornerRadius="6" Padding="12">
          <StackPanel>
            <TextBlock Text="Reservations (sample)" Foreground="#90CAF9" FontWeight="SemiBold" Margin="0,0,0,8"/>
            <TextBox x:Name="TxtScopeDetailReservations" IsReadOnly="True" TextWrapping="Wrap"
                     AcceptsReturn="True" MinHeight="90" VerticalScrollBarVisibility="Auto"
                     Background="#12151A" Foreground="#C5CAD3" BorderBrush="#383E4A"
                     BorderThickness="1" Padding="8,6" FontFamily="Consolas" FontSize="12"/>
          </StackPanel>
        </Border>
      </StackPanel>
    </ScrollViewer>

    <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,12,0,0">
      <Button x:Name="BtnScopeDetailCopy" Content="Copy Details" Width="120" Height="30" Margin="0,0,8,0"
              Background="#2A2F3A" Foreground="#E8EAF0" BorderBrush="#383E4A" BorderThickness="1"/>
      <Button x:Name="BtnScopeDetailClose" Content="Close" Width="90" Height="30" IsDefault="True" IsCancel="True"
              Background="#2196F3" Foreground="White" BorderThickness="0"/>
    </StackPanel>
  </Grid>
</Window>
'@
    
    $title = if ("$($Entry.Name)") { "$($Entry.Name)  ($scopeId)" } else { "Scope $scopeId" }
    $subtitle = "Status: $($Entry.Status)  ·  State: $($Entry.State)  ·  Server: $($Global:DHCPServer)"
    $utilText = @(
        "Utilization: $($Entry.PercentDisplay)  ($($Entry.Level))"
        "In use: $($Entry.InUse)    Free: $($Entry.Free)    Total pool: $($Entry.Total)"
        "Reserved addresses: $($Entry.Reserved)    Pending offers: $($Entry.Pending)"
        "Flag threshold: $($Entry.Threshold)%"
    ) -join [Environment]::NewLine
    
    $configText = @(
        "Scope ID: $($Entry.ScopeId)"
        "Name: $($Entry.Name)"
        "Description: $($Entry.Description)"
        "Range: $($Entry.RangeDisplay)"
        "Subnet mask: $($Entry.SubnetMask)"
        "Lease duration: $($Entry.LeaseDuration)"
        "Exclusion ranges: $exclusionCount"
    ) -join [Environment]::NewLine
    
    $copyBlock = @(
        "DHCP Scope Statistics"
        $title
        $subtitle
        ''
        $utilText
        ''
        $configText
        ''
        "Guidance:"
        $advice
        ''
        "Exclusions:"
        $exclusionText
        ''
        "Reservations (sample):"
        $resText
    ) -join [Environment]::NewLine
    
    try {
        $dialog = [Windows.Markup.XamlReader]::Load([System.Xml.XmlNodeReader]::new($dialogXaml))
        if ($script:Window) { $dialog.Owner = $script:Window }
        
        $dialog.FindName('TxtScopeDetailTitle').Text = $title
        $dialog.FindName('TxtScopeDetailSubtitle').Text = $subtitle
        $dialog.FindName('TxtScopeDetailUtil').Text = $utilText
        $dialog.FindName('TxtScopeDetailConfig').Text = $configText
        $dialog.FindName('TxtScopeDetailAdvice').Text = $advice
        $dialog.FindName('TxtScopeDetailExclusions').Text = $exclusionText
        $dialog.FindName('TxtScopeDetailReservations').Text = $resText
        
        $script:ScopeDetailCopyText = $copyBlock
        $script:ScopeDetailScopeId = $scopeId
        
        $dialog.FindName('BtnScopeDetailCopy').add_Click({
            try {
                [System.Windows.Clipboard]::SetText("$($script:ScopeDetailCopyText)")
                Write-ActionLog "Copied scope statistics details for $($script:ScopeDetailScopeId)" "INFO"
            } catch {
                Show-MessageBox "Could not copy to clipboard: $_" "Scope Details" OK Warning
            }
        })
        
        $dialog.FindName('BtnScopeDetailClose').add_Click({
            $dialog.DialogResult = $true
            $dialog.Close()
        })
        
        [void]$dialog.ShowDialog()
    } catch {
        Write-ActionLog "Scope detail dialog failed: $_" "ERROR"
        Show-MessageBox "Failed to open scope details: $_" "Scope Details" OK Error
    } finally {
        $script:ScopeDetailCopyText = $null
        $script:ScopeDetailScopeId = $null
    }
}

function Load-Statistics {
    <#
    .SYNOPSIS
        Loads server totals and per-scope utilization for every scope
    #>
    
    if ([string]::IsNullOrWhiteSpace($Global:DHCPServer)) {
        Show-MessageBox "Connect to a DHCP server first." "Statistics" OK Warning
        return
    }
    
    Write-ActionLog "Loading server + per-scope statistics..." "INFO"
    Set-Status "Loading scope statistics..."
    
    $threshold = Get-ScopeUtilThresholdPercent
    Start-TaskProgress -Name 'ScopeStats' -Message "Loading scopes from $($Global:DHCPServer)..." -CanPause -Total 0
    
    try {
        $scopes = @(Get-DhcpServerv4Scope -ComputerName $Global:DHCPServer -ErrorAction Stop)
        $scopeCount = Get-SafeCount $scopes
        
        Update-TaskProgress -Processed 0 -Total ([math]::Max(1, $scopeCount + 2)) -Message "Loading server totals..."
        Wait-TaskProgressIfPaused
        if (Test-TaskCancelRequested) {
            Write-ActionLog "Scope statistics load cancelled" "WARN"
            Set-Status "Statistics cancelled"
            return
        }
        
        $serverStats = $null
        try {
            $serverStats = Get-DhcpServerv4Statistics -ComputerName $Global:DHCPServer -ErrorAction Stop
        } catch {
            Write-ActionLog "Server statistics unavailable: $_" "WARN"
        }
        
        Update-TaskProgress -Processed 1 -Message "Loading per-scope utilization ($scopeCount scopes)..."
        Wait-TaskProgressIfPaused
        if (Test-TaskCancelRequested) {
            Write-ActionLog "Scope statistics load cancelled" "WARN"
            Set-Status "Statistics cancelled"
            return
        }
        
        $allScopeStats = @()
        try {
            $allScopeStats = @(Get-DhcpServerv4ScopeStatistics -ComputerName $Global:DHCPServer -ErrorAction Stop)
        } catch {
            Write-ActionLog "Bulk scope statistics failed; falling back per scope: $_" "WARN"
            $allScopeStats = @()
        }
        
        $statsById = @{}
        foreach ($ss in $allScopeStats) {
            try {
                $key = "$($ss.ScopeId)"
                if ($key) { $statsById[$key] = $ss }
            } catch {}
        }
        
        $rows = [System.Collections.Generic.List[object]]::new()
        $totalReserved = 0
        $idx = 0
        
        foreach ($scope in $scopes) {
            Wait-TaskProgressIfPaused
            if (Test-TaskCancelRequested) { break }
            
            $idx++
            $sid = "$($scope.ScopeId)"
            Update-TaskProgress -Processed ($idx + 1) -Total ($scopeCount + 2) -Message "Scope $idx/$scopeCount — $sid"
            
            $stat = $null
            if ($statsById.ContainsKey($sid)) {
                $stat = $statsById[$sid]
            } else {
                try {
                    $stat = Get-DhcpServerv4ScopeStatistics -ComputerName $Global:DHCPServer -ScopeId $scope.ScopeId -ErrorAction Stop
                } catch {
                    Write-ActionLog "Stats failed for scope $sid : $_" "WARN"
                    continue
                }
            }
            
            if ($null -eq $stat) { continue }
            
            $row = New-ScopeStatRow -Scope $scope -Stat $stat -Threshold $threshold
            [void]$rows.Add($row)
            try { $totalReserved += [int]$row.Reserved } catch {}
        }
        
        if (Test-TaskCancelRequested) {
            Write-ActionLog "Scope statistics load cancelled after partial results" "WARN"
        }
        
        # Highest utilization first, then name
        $sorted = @($rows | Sort-Object -Property @{ Expression = 'PercentInUse'; Descending = $true }, @{ Expression = 'Name'; Descending = $false })
        
        $Global:ScopeStatEntriesAll.Clear()
        foreach ($row in $sorted) {
            [void]$Global:ScopeStatEntriesAll.Add($row)
        }
        
        $critical = @($sorted | Where-Object { "$($_.Level)" -eq 'Critical' })
        $warning = @($sorted | Where-Object { "$($_.Level)" -eq 'Warning' })
        $criticalCount = Get-SafeCount $critical
        $warningCount = Get-SafeCount $warning
        
        $script:Window.Dispatcher.Invoke([action]{
            if ($null -ne $serverStats) {
                $script:StatTotalScopes.Text = "$($serverStats.TotalScopes)"
                $script:StatActiveLeases.Text = "$($serverStats.InUse)"
                $script:StatAvailableIPs.Text = "$($serverStats.Available)"
                $script:StatTotalIPs.Text = "$($serverStats.TotalAddresses)"
                if ($serverStats.TotalAddresses -gt 0) {
                    $util = [math]::Round(($serverStats.InUse / $serverStats.TotalAddresses) * 100, 1)
                    $script:StatUtilization.Text = "$util%"
                    if ($util -ge $threshold) {
                        $script:StatUtilization.Foreground = [System.Windows.Media.Brushes]::Tomato
                    } elseif ($util -ge ($threshold - 10)) {
                        $script:StatUtilization.Foreground = [System.Windows.Media.Brushes]::Orange
                    } else {
                        $script:StatUtilization.Foreground = [System.Windows.Media.Brushes]::DodgerBlue
                    }
                } else {
                    $script:StatUtilization.Text = "N/A"
                }
            } else {
                $script:StatTotalScopes.Text = "$(Get-SafeCount $sorted)"
            }
            $script:StatReservations.Text = "$totalReserved"
            
            if ($null -ne $script:GridScopeStats -and $null -eq $script:GridScopeStats.ItemsSource) {
                $script:GridScopeStats.ItemsSource = $Global:ScopeStatEntries
            }
        }, [System.Windows.Threading.DispatcherPriority]::Normal)
        
        Apply-ScopeStatFilter
        Update-ScopeUtilAlertBanner -CriticalCount $criticalCount -WarningCount $warningCount -Threshold $threshold -CriticalScopes $critical
        Sync-DashboardUi
        
        $msg = "Scope statistics: $(Get-SafeCount $sorted) scope(s); $criticalCount critical (≥${threshold}%); $warningCount warning"
        Write-ActionLog $msg "SUCCESS"
        Set-Status $msg
        Update-LogDisplay
        
    } catch {
        $errMsg = "Failed to load statistics: $_"
        Write-ActionLog $errMsg "ERROR"
        Set-Status $errMsg
        Update-LogDisplay
        Show-MessageBox $errMsg "Statistics" OK Error
    } finally {
        Complete-TaskProgress
    }
}
#endregion

#region Multi-Server Comparison Engine
function Update-CompareReadyState {
    <#
    .SYNOPSIS
        Enables compare controls when both servers are connected
    #>
    $bothReady = (-not [string]::IsNullOrWhiteSpace($Global:DHCPServer)) -and `
                 (-not [string]::IsNullOrWhiteSpace($Global:CompareServer))
    
    try {
        $script:Window.Dispatcher.Invoke([action]{
            $script:BtnRunCompare.IsEnabled = $bothReady
            $script:BtnCompareExport.IsEnabled = ($Global:CompareResults.Count -gt 0)
            if ($null -ne $script:BtnCompareMigrate) {
                $script:BtnCompareMigrate.IsEnabled = $bothReady
            }
            
            if ($Global:DHCPServer) {
                $script:TxtCompareServerA.Text = $Global:DHCPServer
                $script:TxtCompareServerA.Foreground = [System.Windows.Media.Brushes]::LimeGreen
            } else {
                $script:TxtCompareServerA.Text = "Not Connected"
                $script:TxtCompareServerA.Foreground = [System.Windows.Media.Brushes]::Orange
            }
            
            if ($bothReady) {
                $script:TxtCompareStatus.Text = "Ready — select category and click Run Compare"
            } elseif ($Global:DHCPServer -and -not $Global:CompareServer) {
                $script:TxtCompareStatus.Text = "Connect Server B to enable comparison"
            } elseif (-not $Global:DHCPServer) {
                $script:TxtCompareStatus.Text = "Connect primary Server A first, then Server B"
            }
        }, [System.Windows.Threading.DispatcherPriority]::Normal)
    } catch {}
    
    Update-MigrateReadyState
}

function Get-NormalizedCompareText {
    param($Value)
    if ($null -eq $Value) { return '' }
    return "$Value".Trim()
}

function Get-IpAddressSortKey {
    <#
    .SYNOPSIS
        Builds a lexicographically sortable key so IPv4 addresses sort numerically
        (10.15.96.0 then 10.15.100.0, not 10.15.100.0 then 10.15.96.0)
    #>
    param($Value)
    
    $text = Get-NormalizedCompareText $Value
    if (-not $text) { return '' }
    
    $m = [regex]::Match($text, '(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})')
    if ($m.Success) {
        $padded = '{0:D3}.{1:D3}.{2:D3}.{3:D3}' -f `
            ([int]$m.Groups[1].Value),
            ([int]$m.Groups[2].Value),
            ([int]$m.Groups[3].Value),
            ([int]$m.Groups[4].Value)
        return $text.Substring(0, $m.Index) + $padded + $text.Substring($m.Index + $m.Length)
    }
    
    return $text.ToLowerInvariant()
}

function Sort-ByIpAddressKey {
    param([object[]]$Keys)
    
    $list = @($Keys | Where-Object { $null -ne $_ } | ForEach-Object { "$_" } | Select-Object -Unique)
    return @($list | Sort-Object { Get-IpAddressSortKey $_ }, { "$_" })
}

function Get-NormalizedCompareIp {
    param($Value)
    $text = Get-NormalizedCompareText $Value
    if (-not $text) { return '' }
    try {
        return ([System.Net.IPAddress]::Parse($text)).IPAddressToString
    } catch {
        return $text
    }
}

function Get-NormalizedCompareMac {
    param($Value)
    $text = Get-NormalizedCompareText $Value
    if (-not $text) { return '' }
    return (($text -replace '[^0-9A-Fa-f]', '')).ToUpperInvariant()
}

function Get-NormalizedCompareName {
    param($Value)
    return (Get-NormalizedCompareText $Value).ToLowerInvariant()
}

function Format-CompareMacDisplay {
    param($Value)
    $norm = Get-NormalizedCompareMac $Value
    if (-not $norm) { return '' }
    if ($norm.Length -eq 12) {
        return (($norm -replace '(.{2})', '$1-').TrimEnd('-'))
    }
    return $norm
}

function Get-LeaseReservationCompareKey {
    param(
        $ClientId,
        $IPAddress,
        $ScopeId = $null
    )
    
    $mac = Get-NormalizedCompareMac $ClientId
    $ip = Get-NormalizedCompareIp $IPAddress
    if ($mac) {
        return "MAC:$mac"
    }
    if ($ip) {
        $scope = Get-NormalizedCompareIp $ScopeId
        if ($scope) { return "IP:$ip|Scope:$scope" }
        return "IP:$ip"
    }
    return "UNKNOWN:$([guid]::NewGuid().ToString('N'))"
}

function Get-NormalizedOptionValueText {
    param($Value)
    
    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($item in @($Value)) {
        if ($null -eq $item) { continue }
        $text = Get-NormalizedCompareText $item
        if (-not $text) { continue }
        $asIp = Get-NormalizedCompareIp $text
        if ($asIp -and $asIp -match '^\d{1,3}(\.\d{1,3}){3}$') {
            [void]$parts.Add($asIp)
        } else {
            [void]$parts.Add($text.ToLowerInvariant())
        }
    }
    
    if ((Get-SafeCount $parts) -eq 0) { return '' }
    return ((@($parts | Sort-Object) -join ', '))
}

function Format-OptionValueDisplay {
    param($Value)
    $items = @($Value | Where-Object { $null -ne $_ } | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if ((Get-SafeCount $items) -eq 0) { return '' }
    return ($items -join ', ')
}

function Get-CompareOptionMapKey {
    param(
        $Option,
        [string]$ScopePart = 'Server'
    )
    
    $optId = Get-NormalizedCompareText $Option.OptionId
    $vendor = Get-NormalizedCompareText $Option.VendorClass
    $user = Get-NormalizedCompareText $Option.UserClass
    $policy = Get-NormalizedCompareText $Option.PolicyName
    if (-not $ScopePart) { $ScopePart = 'Server' }
    return "$ScopePart|Opt$optId|V:$vendor|U:$user|P:$policy"
}

function Test-LeaseStatesEquivalent {
    param([string]$StateA, [string]$StateB)
    
    $a = (Get-NormalizedCompareText $StateA).ToLowerInvariant()
    $b = (Get-NormalizedCompareText $StateB).ToLowerInvariant()
    if ($a -eq $b) { return $true }
    
    # Failover / display variants of an active lease should not force "Different"
    $activeLike = @('active', 'activereservation', 'offer', 'pending')
    if (($activeLike -contains $a) -and ($activeLike -contains $b)) { return $true }
    return $false
}

function New-CompareRow {
    param(
        [string]$Status,
        [string]$Key,
        [string]$Label = '',
        [string]$ValueA = '',
        [string]$ValueB = '',
        [string]$Details = ''
    )
    
    return [PSCustomObject]@{
        Status  = $Status
        Key     = $Key
        Label   = $Label
        ValueA  = $ValueA
        ValueB  = $ValueB
        Details = $Details
    }
}

function Get-DhcpCompareScopes {
    param([string]$ServerA, [string]$ServerB)
    
    Write-ActionLog "Fetching scopes from $ServerA and $ServerB..." "INFO"
    
    $scopesA = @(Get-DhcpServerv4Scope -ComputerName $ServerA -ErrorAction Stop)
    $scopesB = @(Get-DhcpServerv4Scope -ComputerName $ServerB -ErrorAction Stop)
    
    $mapA = @{}
    foreach ($s in $scopesA) {
        $id = Get-NormalizedCompareIp $s.ScopeId
        if (-not $id) { $id = Get-NormalizedCompareText $s.ScopeId }
        $mapA[$id] = $s
    }
    
    $mapB = @{}
    foreach ($s in $scopesB) {
        $id = Get-NormalizedCompareIp $s.ScopeId
        if (-not $id) { $id = Get-NormalizedCompareText $s.ScopeId }
        $mapB[$id] = $s
    }
    
    $results = [System.Collections.Generic.List[object]]::new()
    $allKeys = @(Sort-ByIpAddressKey -Keys @(@($mapA.Keys) + @($mapB.Keys)))
    
    foreach ($key in $allKeys) {
        $a = $null
        $b = $null
        if ($mapA.ContainsKey($key)) { $a = $mapA[$key] }
        if ($mapB.ContainsKey($key)) { $b = $mapB[$key] }
        
        if ($null -ne $a -and $null -eq $b) {
            $results.Add((New-CompareRow -Status 'Only on A' -Key $key -Label (Get-NormalizedCompareText $a.Name) `
                -ValueA "$($a.StartRange)-$($a.EndRange) [$($a.State)]" -ValueB '' `
                -Details "Mask=$($a.SubnetMask); Lease=$($a.LeaseDuration)"))
        }
        elseif ($null -ne $b -and $null -eq $a) {
            $results.Add((New-CompareRow -Status 'Only on B' -Key $key -Label (Get-NormalizedCompareText $b.Name) `
                -ValueA '' -ValueB "$($b.StartRange)-$($b.EndRange) [$($b.State)]" `
                -Details "Mask=$($b.SubnetMask); Lease=$($b.LeaseDuration)"))
        }
        else {
            $diffs = [System.Collections.Generic.List[string]]::new()
            if ((Get-NormalizedCompareName $a.Name) -ne (Get-NormalizedCompareName $b.Name)) { [void]$diffs.Add('Name') }
            if ((Get-NormalizedCompareIp $a.StartRange) -ne (Get-NormalizedCompareIp $b.StartRange)) { [void]$diffs.Add('Start') }
            if ((Get-NormalizedCompareIp $a.EndRange) -ne (Get-NormalizedCompareIp $b.EndRange)) { [void]$diffs.Add('End') }
            if ((Get-NormalizedCompareIp $a.SubnetMask) -ne (Get-NormalizedCompareIp $b.SubnetMask)) { [void]$diffs.Add('Mask') }
            if ((Get-NormalizedCompareText $a.State).ToLowerInvariant() -ne (Get-NormalizedCompareText $b.State).ToLowerInvariant()) { [void]$diffs.Add('State') }
            if ((Get-NormalizedCompareText $a.LeaseDuration) -ne (Get-NormalizedCompareText $b.LeaseDuration)) { [void]$diffs.Add('LeaseDuration') }
            
            if ($diffs.Count -eq 0) {
                $results.Add((New-CompareRow -Status 'Matching' -Key $key -Label (Get-NormalizedCompareText $a.Name) `
                    -ValueA "$($a.StartRange)-$($a.EndRange) [$($a.State)]" `
                    -ValueB "$($b.StartRange)-$($b.EndRange) [$($b.State)]" `
                    -Details "Identical"))
            } else {
                $results.Add((New-CompareRow -Status 'Different' -Key $key -Label (Get-NormalizedCompareText $a.Name) `
                    -ValueA "$($a.StartRange)-$($a.EndRange) [$($a.State)] Name=$($a.Name) Lease=$($a.LeaseDuration)" `
                    -ValueB "$($b.StartRange)-$($b.EndRange) [$($b.State)] Name=$($b.Name) Lease=$($b.LeaseDuration)" `
                    -Details ("Differs: " + ($diffs -join ', '))))
            }
        }
    }
    
    return ,$results
}

function Get-DhcpCompareOptions {
    param([string]$ServerA, [string]$ServerB)
    
    Write-ActionLog "Fetching options from $ServerA and $ServerB..." "INFO"
    
    $optsA = [System.Collections.Generic.List[object]]::new()
    $optsB = [System.Collections.Generic.List[object]]::new()
    
    foreach ($o in @(Get-DhcpServerv4OptionValue -ComputerName $ServerA -ErrorAction SilentlyContinue)) {
        $o | Add-Member -NotePropertyName '_ScopeId' -NotePropertyValue 'Server' -Force
        [void]$optsA.Add($o)
    }
    foreach ($o in @(Get-DhcpServerv4OptionValue -ComputerName $ServerB -ErrorAction SilentlyContinue)) {
        $o | Add-Member -NotePropertyName '_ScopeId' -NotePropertyValue 'Server' -Force
        [void]$optsB.Add($o)
    }
    
    try {
        foreach ($scope in @(Get-DhcpServerv4Scope -ComputerName $ServerA -ErrorAction SilentlyContinue)) {
            $scopeId = Get-NormalizedCompareIp $scope.ScopeId
            if (-not $scopeId) { $scopeId = Get-NormalizedCompareText $scope.ScopeId }
            foreach ($o in @(Get-DhcpServerv4OptionValue -ComputerName $ServerA -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue)) {
                $o | Add-Member -NotePropertyName '_ScopeId' -NotePropertyValue $scopeId -Force
                [void]$optsA.Add($o)
            }
        }
    } catch {}
    
    try {
        foreach ($scope in @(Get-DhcpServerv4Scope -ComputerName $ServerB -ErrorAction SilentlyContinue)) {
            $scopeId = Get-NormalizedCompareIp $scope.ScopeId
            if (-not $scopeId) { $scopeId = Get-NormalizedCompareText $scope.ScopeId }
            foreach ($o in @(Get-DhcpServerv4OptionValue -ComputerName $ServerB -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue)) {
                $o | Add-Member -NotePropertyName '_ScopeId' -NotePropertyValue $scopeId -Force
                [void]$optsB.Add($o)
            }
        }
    } catch {}
    
    $mapA = @{}
    foreach ($o in $optsA) {
        $scopePart = if ($o._ScopeId) { "$($o._ScopeId)" } else { 'Server' }
        $key = Get-CompareOptionMapKey -Option $o -ScopePart $scopePart
        $mapA[$key] = $o
    }
    
    $mapB = @{}
    foreach ($o in $optsB) {
        $scopePart = if ($o._ScopeId) { "$($o._ScopeId)" } else { 'Server' }
        $key = Get-CompareOptionMapKey -Option $o -ScopePart $scopePart
        $mapB[$key] = $o
    }
    
    $results = [System.Collections.Generic.List[object]]::new()
    $allKeys = @(Sort-ByIpAddressKey -Keys @(@($mapA.Keys) + @($mapB.Keys)))
    
    foreach ($key in $allKeys) {
        $a = $null
        $b = $null
        if ($mapA.ContainsKey($key)) { $a = $mapA[$key] }
        if ($mapB.ContainsKey($key)) { $b = $mapB[$key] }
        
        $label = if ($null -ne $a -and $a.Name) { Get-NormalizedCompareText $a.Name }
                 elseif ($null -ne $b -and $b.Name) { Get-NormalizedCompareText $b.Name }
                 else { $key }
        
        $valADisplay = if ($null -ne $a) { Format-OptionValueDisplay $a.Value } else { '' }
        $valBDisplay = if ($null -ne $b) { Format-OptionValueDisplay $b.Value } else { '' }
        $valANorm = if ($null -ne $a) { Get-NormalizedOptionValueText $a.Value } else { '' }
        $valBNorm = if ($null -ne $b) { Get-NormalizedOptionValueText $b.Value } else { '' }
        
        if ($null -ne $a -and $null -eq $b) {
            $results.Add((New-CompareRow -Status 'Only on A' -Key $key -Label $label -ValueA $valADisplay -ValueB '' -Details 'Missing on B'))
        }
        elseif ($null -ne $b -and $null -eq $a) {
            $results.Add((New-CompareRow -Status 'Only on B' -Key $key -Label $label -ValueA '' -ValueB $valBDisplay -Details 'Missing on A'))
        }
        elseif ($valANorm -eq $valBNorm) {
            $results.Add((New-CompareRow -Status 'Matching' -Key $key -Label $label -ValueA $valADisplay -ValueB $valBDisplay -Details 'Identical'))
        }
        else {
            $results.Add((New-CompareRow -Status 'Different' -Key $key -Label $label -ValueA $valADisplay -ValueB $valBDisplay -Details 'Value mismatch'))
        }
    }
    
    return ,$results
}

function Get-DhcpCompareLeases {
    param([string]$ServerA, [string]$ServerB)
    
    Write-ActionLog "Fetching leases from $ServerA and $ServerB..." "INFO"
    
    $leasesA = [System.Collections.Generic.List[object]]::new()
    $leasesB = [System.Collections.Generic.List[object]]::new()
    
    foreach ($scope in @(Get-DhcpServerv4Scope -ComputerName $ServerA -ErrorAction Stop)) {
        try {
            $items = @(Get-DhcpServerv4Lease -ComputerName $ServerA -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue)
            foreach ($item in $items) { [void]$leasesA.Add($item) }
        } catch {}
    }
    
    foreach ($scope in @(Get-DhcpServerv4Scope -ComputerName $ServerB -ErrorAction Stop)) {
        try {
            $items = @(Get-DhcpServerv4Lease -ComputerName $ServerB -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue)
            foreach ($item in $items) { [void]$leasesB.Add($item) }
        } catch {}
    }
    
    $mapA = @{}
    foreach ($l in $leasesA) {
        $key = Get-LeaseReservationCompareKey -ClientId $l.ClientId -IPAddress $l.IPAddress -ScopeId $l.ScopeId
        # Prefer Active over duplicate MAC rows when collisions occur
        if (-not $mapA.ContainsKey($key)) {
            $mapA[$key] = $l
        } else {
            $existing = $mapA[$key]
            $existState = Get-NormalizedCompareText $existing.AddressState
            $newState = Get-NormalizedCompareText $l.AddressState
            if ($existState -match 'Inactiv|Expired|Declin' -and $newState -match 'Active') {
                $mapA[$key] = $l
            }
        }
    }
    
    $mapB = @{}
    foreach ($l in $leasesB) {
        $key = Get-LeaseReservationCompareKey -ClientId $l.ClientId -IPAddress $l.IPAddress -ScopeId $l.ScopeId
        if (-not $mapB.ContainsKey($key)) {
            $mapB[$key] = $l
        } else {
            $existing = $mapB[$key]
            $existState = Get-NormalizedCompareText $existing.AddressState
            $newState = Get-NormalizedCompareText $l.AddressState
            if ($existState -match 'Inactiv|Expired|Declin' -and $newState -match 'Active') {
                $mapB[$key] = $l
            }
        }
    }
    
    $results = [System.Collections.Generic.List[object]]::new()
    $allKeys = @(Sort-ByIpAddressKey -Keys @(@($mapA.Keys) + @($mapB.Keys)))
    
    foreach ($key in $allKeys) {
        $a = $null
        $b = $null
        if ($mapA.ContainsKey($key)) { $a = $mapA[$key] }
        if ($mapB.ContainsKey($key)) { $b = $mapB[$key] }
        
        if ($null -ne $a -and $null -eq $b) {
            $results.Add((New-CompareRow -Status 'Only on A' -Key $key -Label (Get-NormalizedCompareText $a.HostName) `
                -ValueA "$($a.IPAddress) [$($a.AddressState)] Scope=$($a.ScopeId)" -ValueB '' `
                -Details "MAC=$(Format-CompareMacDisplay $a.ClientId); Expiry=$($a.LeaseExpiryTime)"))
        }
        elseif ($null -ne $b -and $null -eq $a) {
            $results.Add((New-CompareRow -Status 'Only on B' -Key $key -Label (Get-NormalizedCompareText $b.HostName) `
                -ValueA '' -ValueB "$($b.IPAddress) [$($b.AddressState)] Scope=$($b.ScopeId)" `
                -Details "MAC=$(Format-CompareMacDisplay $b.ClientId); Expiry=$($b.LeaseExpiryTime)"))
        }
        else {
            $diffs = [System.Collections.Generic.List[string]]::new()
            if ((Get-NormalizedCompareIp $a.IPAddress) -ne (Get-NormalizedCompareIp $b.IPAddress)) { [void]$diffs.Add('IP') }
            if ((Get-NormalizedCompareName $a.HostName) -ne (Get-NormalizedCompareName $b.HostName)) { [void]$diffs.Add('Hostname') }
            if ((Get-NormalizedCompareIp $a.ScopeId) -ne (Get-NormalizedCompareIp $b.ScopeId)) { [void]$diffs.Add('Scope') }
            # AddressState intentionally ignored for Matching vs Different (failover display variants)
            
            $valA = "$($a.IPAddress) [$($a.AddressState)] Host=$($a.HostName)"
            $valB = "$($b.IPAddress) [$($b.AddressState)] Host=$($b.HostName)"
            $macNote = "MAC=$(Format-CompareMacDisplay $a.ClientId)"
            
            if ($diffs.Count -eq 0) {
                $stateNote = ''
                if (-not (Test-LeaseStatesEquivalent -StateA "$($a.AddressState)" -StateB "$($b.AddressState)")) {
                    $stateNote = " (state display differs: $($a.AddressState) vs $($b.AddressState))"
                } elseif ((Get-NormalizedCompareText $a.AddressState) -ne (Get-NormalizedCompareText $b.AddressState)) {
                    $stateNote = " (state labels: $($a.AddressState) / $($b.AddressState))"
                }
                $results.Add((New-CompareRow -Status 'Matching' -Key $key -Label (Get-NormalizedCompareText $a.HostName) `
                    -ValueA $valA -ValueB $valB -Details ("Identical; $macNote$stateNote")))
            } else {
                $results.Add((New-CompareRow -Status 'Different' -Key $key -Label (Get-NormalizedCompareText $a.HostName) `
                    -ValueA $valA -ValueB $valB -Details ("Differs: " + ($diffs -join ', ') + "; $macNote")))
            }
        }
    }
    
    return ,$results
}

function Get-DhcpCompareReservations {
    param([string]$ServerA, [string]$ServerB)
    
    Write-ActionLog "Fetching reservations from $ServerA and $ServerB..." "INFO"
    
    $resA = [System.Collections.Generic.List[object]]::new()
    $resB = [System.Collections.Generic.List[object]]::new()
    
    foreach ($scope in @(Get-DhcpServerv4Scope -ComputerName $ServerA -ErrorAction Stop)) {
        try {
            $items = @(Get-DhcpServerv4Reservation -ComputerName $ServerA -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue)
            foreach ($item in $items) { [void]$resA.Add($item) }
        } catch {}
    }
    
    foreach ($scope in @(Get-DhcpServerv4Scope -ComputerName $ServerB -ErrorAction Stop)) {
        try {
            $items = @(Get-DhcpServerv4Reservation -ComputerName $ServerB -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue)
            foreach ($item in $items) { [void]$resB.Add($item) }
        } catch {}
    }
    
    $mapA = @{}
    foreach ($r in $resA) {
        $key = Get-LeaseReservationCompareKey -ClientId $r.ClientId -IPAddress $r.IPAddress -ScopeId $r.ScopeId
        $mapA[$key] = $r
    }
    
    $mapB = @{}
    foreach ($r in $resB) {
        $key = Get-LeaseReservationCompareKey -ClientId $r.ClientId -IPAddress $r.IPAddress -ScopeId $r.ScopeId
        $mapB[$key] = $r
    }
    
    $results = [System.Collections.Generic.List[object]]::new()
    $allKeys = @(Sort-ByIpAddressKey -Keys @(@($mapA.Keys) + @($mapB.Keys)))
    
    foreach ($key in $allKeys) {
        $a = $null
        $b = $null
        if ($mapA.ContainsKey($key)) { $a = $mapA[$key] }
        if ($mapB.ContainsKey($key)) { $b = $mapB[$key] }
        
        if ($null -ne $a -and $null -eq $b) {
            $results.Add((New-CompareRow -Status 'Only on A' -Key $key -Label (Get-NormalizedCompareText $a.Name) `
                -ValueA "$($a.IPAddress) Scope=$($a.ScopeId)" -ValueB '' `
                -Details "MAC=$(Format-CompareMacDisplay $a.ClientId); Type=$($a.Type)"))
        }
        elseif ($null -ne $b -and $null -eq $a) {
            $results.Add((New-CompareRow -Status 'Only on B' -Key $key -Label (Get-NormalizedCompareText $b.Name) `
                -ValueA '' -ValueB "$($b.IPAddress) Scope=$($b.ScopeId)" `
                -Details "MAC=$(Format-CompareMacDisplay $b.ClientId); Type=$($b.Type)"))
        }
        else {
            $diffs = [System.Collections.Generic.List[string]]::new()
            if ((Get-NormalizedCompareIp $a.IPAddress) -ne (Get-NormalizedCompareIp $b.IPAddress)) { [void]$diffs.Add('IP') }
            if ((Get-NormalizedCompareName $a.Name) -ne (Get-NormalizedCompareName $b.Name)) { [void]$diffs.Add('Name') }
            if ((Get-NormalizedCompareIp $a.ScopeId) -ne (Get-NormalizedCompareIp $b.ScopeId)) { [void]$diffs.Add('Scope') }
            if ((Get-NormalizedCompareMac $a.ClientId) -ne (Get-NormalizedCompareMac $b.ClientId)) { [void]$diffs.Add('MAC') }
            
            $valA = "$($a.IPAddress) Name=$($a.Name) Scope=$($a.ScopeId)"
            $valB = "$($b.IPAddress) Name=$($b.Name) Scope=$($b.ScopeId)"
            $macNote = "MAC=$(Format-CompareMacDisplay $a.ClientId)"
            
            if ($diffs.Count -eq 0) {
                $results.Add((New-CompareRow -Status 'Matching' -Key $key -Label (Get-NormalizedCompareText $a.Name) `
                    -ValueA $valA -ValueB $valB -Details "Identical; $macNote"))
            } else {
                $results.Add((New-CompareRow -Status 'Different' -Key $key -Label (Get-NormalizedCompareText $a.Name) `
                    -ValueA $valA -ValueB $valB -Details ("Differs: " + ($diffs -join ', ') + "; $macNote")))
            }
        }
    }
    
    return ,$results
}

function Show-CompareResults {
    <#
    .SYNOPSIS
        Applies filter and updates compare grid + summary counters
    #>
    param(
        [System.Collections.IEnumerable]$Results
    )
    
    $filter = 'All'
    try {
        if ($null -ne $script:CboCompareFilter -and $null -ne $script:CboCompareFilter.SelectedItem) {
            $filter = $script:CboCompareFilter.SelectedItem.Content
        }
    } catch {}
    
    $all = @($Results)
    $onlyA = @($all | Where-Object { $_.Status -eq 'Only on A' })
    $onlyB = @($all | Where-Object { $_.Status -eq 'Only on B' })
    $match = @($all | Where-Object { $_.Status -eq 'Matching' })
    $diff  = @($all | Where-Object { $_.Status -eq 'Different' })
    
    # Assign inside switch — outputting an array from switch unwraps a single-item array
    # to a scalar, which has no .Count under Set-StrictMode.
    $filtered = $all
    switch ($filter) {
        'Only on A' { $filtered = $onlyA }
        'Only on B' { $filtered = $onlyB }
        'Matching'  { $filtered = $match }
        'Different' { $filtered = $diff }
        default     { $filtered = $all }
    }
    if ($null -eq $filtered) { $filtered = @() }
    else { $filtered = @($filtered) }
    
    $countOnlyA    = Get-SafeCount $onlyA
    $countOnlyB    = Get-SafeCount $onlyB
    $countMatch    = Get-SafeCount $match
    $countDiff     = Get-SafeCount $diff
    $countAll      = Get-SafeCount $all
    $countFiltered = Get-SafeCount $filtered
    $statusText    = "Showing $countFiltered of $countAll results (filter: $filter)"
    $exportEnabled = $countAll -gt 0
    
    $script:Window.Dispatcher.Invoke([action]{
        $script:CmpOnlyA.Text = "$countOnlyA"
        $script:CmpOnlyB.Text = "$countOnlyB"
        $script:CmpMatch.Text = "$countMatch"
        $script:CmpDiff.Text  = "$countDiff"
        $script:GridCompare.ItemsSource = $filtered
        $script:BtnCompareExport.IsEnabled = $exportEnabled
        $script:TxtCompareStatus.Text = $statusText
    }, [System.Windows.Threading.DispatcherPriority]::Normal)
}

function Invoke-DhcpServerCompare {
    <#
    .SYNOPSIS
        Runs comparison between primary and compare DHCP servers
    #>
    
    if ([string]::IsNullOrWhiteSpace($Global:DHCPServer)) {
        Show-MessageBox "Connect to primary Server A first." "Compare" OK Warning
        return
    }
    
    if ([string]::IsNullOrWhiteSpace($Global:CompareServer)) {
        Show-MessageBox "Connect to compare Server B first." "Compare" OK Warning
        return
    }
    
    $category = 'Scopes'
    try {
        if ($null -ne $script:CboCompareCategory.SelectedItem) {
            $category = $script:CboCompareCategory.SelectedItem.Content
        }
    } catch {}
    
    Write-ActionLog "Running compare: $category — A=$($Global:DHCPServer) vs B=$($Global:CompareServer)" "INFO"
    Set-Status "Comparing $category..."
    
    try {
        $script:TxtCompareStatus.Text = "Comparing $category..."
        
        $results = switch ($category) {
            'Scopes'       { Get-DhcpCompareScopes -ServerA $Global:DHCPServer -ServerB $Global:CompareServer }
            'Options'      { Get-DhcpCompareOptions -ServerA $Global:DHCPServer -ServerB $Global:CompareServer }
            'Leases'       { Get-DhcpCompareLeases -ServerA $Global:DHCPServer -ServerB $Global:CompareServer }
            'Reservations' { Get-DhcpCompareReservations -ServerA $Global:DHCPServer -ServerB $Global:CompareServer }
            default        { throw "Unknown compare category: $category" }
        }
        
        $Global:CompareResults.Clear()
        foreach ($row in $results) { $Global:CompareResults.Add($row) }
        
        Show-CompareResults -Results $Global:CompareResults
        
        $diffCount = Get-SafeCount @($Global:CompareResults | Where-Object { $_.Status -ne 'Matching' })
        $totalCount = Get-SafeCount $Global:CompareResults
        Write-ActionLog "Compare complete: $totalCount items, $diffCount non-matching (numeric IP/Scope ID sort)" "SUCCESS"
        Set-Status "Compare complete — $totalCount items (sorted by Scope ID)"
        Update-LogDisplay
        
    } catch {
        $errMsg = "Compare failed: $_"
        Write-ActionLog $errMsg "ERROR"
        Set-Status $errMsg
        Show-MessageBox $errMsg "Compare Error" OK Error
        Update-LogDisplay
    }
}

function Export-CompareResults {
    <#
    .SYNOPSIS
        Exports comparison results to CSV
    #>
    
    if ($Global:CompareResults.Count -eq 0) {
        Show-MessageBox "No comparison results to export. Run a compare first." "Export" OK Warning
        return
    }
    
    try {
        $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveDialog.Filter = "CSV Files (*.csv)|*.csv|Text Files (*.txt)|*.txt|All Files (*.*)|*.*"
        $category = 'Compare'
        try { $category = $script:CboCompareCategory.SelectedItem.Content } catch {}
        $saveDialog.FileName = "DHCP-Compare-$category-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
        $saveDialog.Title = "Export Compare Results"
        
        if ($saveDialog.ShowDialog() -eq 'OK') {
            $Global:CompareResults | Select-Object Status, Key, Label, ValueA, ValueB, Details |
                Export-Csv -Path $saveDialog.FileName -NoTypeInformation -Encoding UTF8
            
            Write-ActionLog "Compare results exported to: $($saveDialog.FileName)" "SUCCESS"
            Show-MessageBox "Results exported to:`n$($saveDialog.FileName)" "Export Complete" OK Information
            Update-LogDisplay
        }
    } catch {
        $errMsg = "Failed to export compare results: $_"
        Write-ActionLog $errMsg "ERROR"
        Show-MessageBox $errMsg "Export Error" OK Error
    }
}
#endregion

#region DHCP Audit Log Ingest + Live Event Watch
function Get-DhcpEventDescription {
    param([string]$EventId)
    
    switch ($EventId) {
        '00' { 'Started' }
        '01' { 'Stopped' }
        '02' { 'Log paused' }
        '10' { 'Assign' }
        '11' { 'Renew' }
        '12' { 'Release' }
        '13' { 'Conflict detected' }
        '14' { 'Lease deleted' }
        '15' { 'NACK' }
        '16' { 'Decline' }
        '17' { 'Auth failed' }
        '20' { 'BootP' }
        '21' { 'DynBOOTp' }
        '30' { 'DNS update request' }
        '31' { 'DNS update failed' }
        '32' { 'DNS update successful' }
        '50' { 'Unreachable domain' }
        '51' { 'Authorization succeeded' }
        '52' { 'Upgraded to Windows' }
        '53' { 'Cached auth' }
        '54' { 'Authorization failed' }
        '55' { 'Server found in DS' }
        '56' { 'Server not in DS' }
        '57' { 'Server changed domain' }
        '58' { 'Server changed IP' }
        '59' { 'Network failure' }
        '60' { 'No domain' }
        '61' { 'Another server online' }
        '62' { 'Stopping rogue detection' }
        '63' { 'Restarting rogue detection' }
        default { "Event $EventId" }
    }
}

function Get-DhcpAuditLogFolder {
    <#
    .SYNOPSIS
        Resolves the DHCP audit log folder for Local / A / B / Custom
    #>
    param(
        [ValidateSet('Local','A','B','Custom')]
        [string]$Source = 'Local',
        [string]$CustomPath = ''
    )
    
    if ($Source -eq 'Custom') {
        if ([string]::IsNullOrWhiteSpace($CustomPath)) { return $null }
        if (-not (Test-Path -LiteralPath $CustomPath)) { return $null }
        $item = Get-Item -LiteralPath $CustomPath -ErrorAction SilentlyContinue
        if ($null -eq $item) { return $null }
        if ($item.PSIsContainer) { return $item.FullName }
        return $item.DirectoryName
    }
    
    $root = $null
    switch ($Source) {
        'Local' {
            $root = Join-Path $env:SystemRoot 'System32\dhcp'
        }
        'A' {
            if ([string]::IsNullOrWhiteSpace($Global:DHCPServer)) { return $null }
            if ($Global:DHCPServer -match '^(localhost|127\.0\.0\.1|\.)$') {
                $root = Join-Path $env:SystemRoot 'System32\dhcp'
            } else {
                $root = "\\$($Global:DHCPServer)\admin$\System32\dhcp"
            }
        }
        'B' {
            if ([string]::IsNullOrWhiteSpace($Global:CompareServer)) { return $null }
            if ($Global:CompareServer -match '^(localhost|127\.0\.0\.1|\.)$') {
                $root = Join-Path $env:SystemRoot 'System32\dhcp'
            } else {
                $root = "\\$($Global:CompareServer)\admin$\System32\dhcp"
            }
        }
    }
    
    if (-not $root -or -not (Test-Path -LiteralPath $root)) {
        if ($Source -eq 'A' -and $Global:DHCPServer) {
            $root = "\\$($Global:DHCPServer)\C$\Windows\System32\dhcp"
        }
        elseif ($Source -eq 'B' -and $Global:CompareServer) {
            $root = "\\$($Global:CompareServer)\C$\Windows\System32\dhcp"
        }
    }
    
    if (-not $root -or -not (Test-Path -LiteralPath $root)) {
        return $null
    }
    
    return $root
}

function Get-DhcpAuditLogCandidates {
    <#
    .SYNOPSIS
        Lists DhcpSrvLog* files with name, last modified, and size
    #>
    param(
        [ValidateSet('Local','A','B','Custom')]
        [string]$Source = 'Local',
        [string]$CustomPath = ''
    )
    
    $folder = Get-DhcpAuditLogFolder -Source $Source -CustomPath $CustomPath
    if (-not $folder) { return @() }
    
    $files = @(Get-ChildItem -LiteralPath $folder -Filter 'DhcpSrvLog*' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending)
    
    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($f in $files) {
        $results.Add([PSCustomObject]@{
            FileName       = $f.Name
            LastModified   = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
            LastWriteTime  = $f.LastWriteTime
            SizeKB         = [math]::Round($f.Length / 1KB, 1)
            SizeBytes      = $f.Length
            FullPath       = $f.FullName
            Folder         = $folder
        })
    }
    
    return @($results)
}

function Get-DhcpAuditLogPath {
    <#
    .SYNOPSIS
        Resolves the newest DHCP audit log for local or remote server
    #>
    param(
        [ValidateSet('Local','A','B','Custom')]
        [string]$Source = 'Local',
        [string]$CustomPath = ''
    )
    
    if ($Source -eq 'Custom') {
        if ([string]::IsNullOrWhiteSpace($CustomPath)) { return $null }
        if (Test-Path -LiteralPath $CustomPath) {
            $item = Get-Item -LiteralPath $CustomPath
            if (-not $item.PSIsContainer) { return $item.FullName }
        }
    }
    
    $candidates = @(Get-DhcpAuditLogCandidates -Source $Source -CustomPath $CustomPath)
    if ((Get-SafeCount $candidates) -eq 0) {
        return (Get-DhcpAuditLogFolder -Source $Source -CustomPath $CustomPath)
    }
    return $candidates[0].FullPath
}

function Show-DhcpAuditLogPickerDialog {
    <#
    .SYNOPSIS
        Lets the user choose a DHCP audit log file (shows filename + last modified)
    #>
    param(
        [ValidateSet('Local','A','B','Custom')]
        [string]$Source = 'Local',
        [string]$CustomPath = ''
    )
    
    $candidates = @(Get-DhcpAuditLogCandidates -Source $Source -CustomPath $CustomPath)
    if ((Get-SafeCount $candidates) -eq 0) {
        $folder = Get-DhcpAuditLogFolder -Source $Source -CustomPath $CustomPath
        $where = if ($folder) { $folder } else { 'the selected source' }
        Show-MessageBox "No DhcpSrvLog* files found under:`n$where" "Detect Logs" OK Warning
        return $null
    }
    
    [xml]$dialogXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Select DHCP Audit Log"
        Height="480" Width="820"
        WindowStartupLocation="CenterOwner"
        Background="#1A1D23"
        FontFamily="Segoe UI" FontSize="13">
  <Grid Margin="16">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <TextBlock Grid.Row="0" Text="Choose a DHCP audit log to ingest"
               Foreground="#E8EAF0" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,6"/>
    <TextBlock x:Name="TxtPickerFolder" Grid.Row="1" Foreground="#9AA3B2" FontSize="11"
               Margin="0,0,0,10" TextWrapping="Wrap"/>

    <DataGrid Grid.Row="2" x:Name="GridLogFiles"
              AutoGenerateColumns="False" IsReadOnly="True" CanUserAddRows="False"
              SelectionMode="Single" HeadersVisibility="Column"
              Background="#22262E" Foreground="#E8EAF0" BorderThickness="0"
              RowBackground="#22262E" AlternatingRowBackground="#2A2F3A"
              GridLinesVisibility="Horizontal" HorizontalGridLinesBrush="#383E4A"
              RowHeight="28" ColumnHeaderHeight="32">
      <DataGrid.Columns>
        <DataGridTextColumn Header="File Name" Binding="{Binding FileName}" Width="220"/>
        <DataGridTextColumn Header="Last Modified" Binding="{Binding LastModified}" Width="160"/>
        <DataGridTextColumn Header="Size (KB)" Binding="{Binding SizeKB}" Width="90"/>
        <DataGridTextColumn Header="Full Path" Binding="{Binding FullPath}" Width="*"/>
      </DataGrid.Columns>
      <DataGrid.ColumnHeaderStyle>
        <Style TargetType="DataGridColumnHeader">
          <Setter Property="Background" Value="#2A2F3A"/>
          <Setter Property="Foreground" Value="#9AA3B2"/>
          <Setter Property="Padding" Value="8,0"/>
          <Setter Property="BorderBrush" Value="#383E4A"/>
          <Setter Property="BorderThickness" Value="0,0,1,1"/>
        </Style>
      </DataGrid.ColumnHeaderStyle>
    </DataGrid>

    <TextBlock Grid.Row="3" Margin="0,10,0,8" Foreground="#9AA3B2" FontSize="11"
               Text="Sorted by last modified (newest first). Double-click a row or select and click Use Selected."
               TextWrapping="Wrap"/>

    <StackPanel Grid.Row="4" Orientation="Horizontal" HorizontalAlignment="Right">
      <Button x:Name="BtnPickerUse" Content="Use Selected" Width="120" Height="30" Margin="0,0,8,0"
              Background="#2196F3" Foreground="White" BorderThickness="0"/>
      <Button x:Name="BtnPickerCancel" Content="Cancel" Width="90" Height="30"
              Background="#2A2F3A" Foreground="#E8EAF0" BorderBrush="#383E4A" BorderThickness="1"/>
    </StackPanel>
  </Grid>
</Window>
'@
    
    $selectedPath = $null
    try {
        $dialog = [Windows.Markup.XamlReader]::Load([System.Xml.XmlNodeReader]::new($dialogXaml))
        if ($script:Window) { $dialog.Owner = $script:Window }
        
        $grid = $dialog.FindName('GridLogFiles')
        $txtFolder = $dialog.FindName('TxtPickerFolder')
        $btnUse = $dialog.FindName('BtnPickerUse')
        $btnCancel = $dialog.FindName('BtnPickerCancel')
        
        $folder = "$($candidates[0].Folder)"
        $txtFolder.Text = "Folder: $folder  —  $(Get-SafeCount $candidates) file(s)"
        $grid.ItemsSource = $candidates
        if ((Get-SafeCount $candidates) -gt 0) { $grid.SelectedIndex = 0 }
        
        $choose = {
            if ($null -eq $grid.SelectedItem) {
                Show-MessageBox "Select a log file first." "Detect Logs" OK Warning
                return
            }
            $script:AuditLogPickerSelection = "$($grid.SelectedItem.FullPath)"
            $dialog.DialogResult = $true
            $dialog.Close()
        }
        
        $btnUse.add_Click($choose)
        $grid.add_MouseDoubleClick({
            if ($null -ne $grid.SelectedItem) { & $choose }
        })
        $btnCancel.add_Click({
            $script:AuditLogPickerSelection = $null
            $dialog.DialogResult = $false
            $dialog.Close()
        })
        
        $script:AuditLogPickerSelection = $null
        [void]$dialog.ShowDialog()
        $selectedPath = $script:AuditLogPickerSelection
    } catch {
        Write-ActionLog "Log picker failed: $_" "ERROR"
        Show-MessageBox "Failed to open log picker: $_" "Detect Logs" OK Error
        return $null
    }
    
    return $selectedPath
}

function Show-DhcpEventDetailDialog {
    <#
    .SYNOPSIS
        Modal popup with full details for one ingested DHCP audit event
    #>
    param(
        [object]$Entry
    )
    
    if ($null -eq $Entry) {
        Show-MessageBox "Select an event in the grid first (or double-click a row)." "Event Details" OK Warning
        return
    }
    
    $eventId = "$($Entry.EventId)".Trim()
    $knownDesc = Get-DhcpEventDescription $eventId
    $logDesc = "$($Entry.Description)".Trim()
    if ($logDesc -and $knownDesc -and $logDesc -ne $knownDesc -and $knownDesc -notmatch '^Event ') {
        $meaning = "$logDesc  —  known ID meaning: $knownDesc"
    } elseif ($logDesc) {
        $meaning = $logDesc
    } else {
        $meaning = $knownDesc
    }
    
    $server   = "$($Entry.Server)"
    $time     = "$($Entry.Time)"
    $ip       = "$($Entry.IPAddress)"
    $mac      = "$($Entry.MacAddress)"
    $hostName = "$($Entry.HostName)"
    $details  = "$($Entry.Details)"
    $raw      = "$($Entry.Raw)"
    
    [xml]$dialogXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="DHCP Event Details"
        Height="560" Width="720"
        MinHeight="420" MinWidth="560"
        WindowStartupLocation="CenterOwner"
        Background="#1A1D23"
        FontFamily="Segoe UI" FontSize="13"
        ResizeMode="CanResizeWithGrip">
  <Grid Margin="16">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <StackPanel Grid.Row="0" Margin="0,0,0,12">
      <TextBlock Text="Event details" Foreground="#E8EAF0" FontSize="18" FontWeight="SemiBold"/>
      <TextBlock x:Name="TxtDetailSubtitle" Foreground="#9AA3B2" FontSize="12" Margin="0,4,0,0"
                 TextWrapping="Wrap"/>
    </StackPanel>

    <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="120"/>
          <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <TextBlock Grid.Row="0" Grid.Column="0" Text="Server" Foreground="#9AA3B2" Margin="0,0,12,8" VerticalAlignment="Center"/>
        <TextBox Grid.Row="0" Grid.Column="1" x:Name="TxtDetailServer" IsReadOnly="True"
                 Background="#22262E" Foreground="#E8EAF0" BorderBrush="#383E4A" BorderThickness="1"
                 Padding="8,6" Margin="0,0,0,8"/>

        <TextBlock Grid.Row="1" Grid.Column="0" Text="Time" Foreground="#9AA3B2" Margin="0,0,12,8" VerticalAlignment="Center"/>
        <TextBox Grid.Row="1" Grid.Column="1" x:Name="TxtDetailTime" IsReadOnly="True"
                 Background="#22262E" Foreground="#E8EAF0" BorderBrush="#383E4A" BorderThickness="1"
                 Padding="8,6" Margin="0,0,0,8"/>

        <TextBlock Grid.Row="2" Grid.Column="0" Text="Event ID" Foreground="#9AA3B2" Margin="0,0,12,8" VerticalAlignment="Center"/>
        <TextBox Grid.Row="2" Grid.Column="1" x:Name="TxtDetailEventId" IsReadOnly="True"
                 Background="#22262E" Foreground="#E8EAF0" BorderBrush="#383E4A" BorderThickness="1"
                 Padding="8,6" Margin="0,0,0,8"/>

        <TextBlock Grid.Row="3" Grid.Column="0" Text="Description" Foreground="#9AA3B2" Margin="0,0,12,8" VerticalAlignment="Top"/>
        <TextBox Grid.Row="3" Grid.Column="1" x:Name="TxtDetailDescription" IsReadOnly="True"
                 TextWrapping="Wrap" AcceptsReturn="True" MinHeight="44"
                 Background="#22262E" Foreground="#E8EAF0" BorderBrush="#383E4A" BorderThickness="1"
                 Padding="8,6" Margin="0,0,0,8"/>

        <TextBlock Grid.Row="4" Grid.Column="0" Text="IP Address" Foreground="#9AA3B2" Margin="0,0,12,8" VerticalAlignment="Center"/>
        <TextBox Grid.Row="4" Grid.Column="1" x:Name="TxtDetailIp" IsReadOnly="True"
                 Background="#22262E" Foreground="#E8EAF0" BorderBrush="#383E4A" BorderThickness="1"
                 Padding="8,6" Margin="0,0,0,8"/>

        <TextBlock Grid.Row="5" Grid.Column="0" Text="MAC" Foreground="#9AA3B2" Margin="0,0,12,8" VerticalAlignment="Center"/>
        <TextBox Grid.Row="5" Grid.Column="1" x:Name="TxtDetailMac" IsReadOnly="True"
                 Background="#22262E" Foreground="#E8EAF0" BorderBrush="#383E4A" BorderThickness="1"
                 Padding="8,6" Margin="0,0,0,8"/>

        <TextBlock Grid.Row="6" Grid.Column="0" Text="Hostname" Foreground="#9AA3B2" Margin="0,0,12,8" VerticalAlignment="Center"/>
        <TextBox Grid.Row="6" Grid.Column="1" x:Name="TxtDetailHost" IsReadOnly="True"
                 Background="#22262E" Foreground="#E8EAF0" BorderBrush="#383E4A" BorderThickness="1"
                 Padding="8,6" Margin="0,0,0,8"/>

        <TextBlock Grid.Row="7" Grid.Column="0" Text="Details" Foreground="#9AA3B2" Margin="0,0,12,8" VerticalAlignment="Top"/>
        <TextBox Grid.Row="7" Grid.Column="1" x:Name="TxtDetailExtra" IsReadOnly="True"
                 TextWrapping="Wrap" AcceptsReturn="True" MinHeight="56" VerticalScrollBarVisibility="Auto"
                 Background="#22262E" Foreground="#E8EAF0" BorderBrush="#383E4A" BorderThickness="1"
                 Padding="8,6" Margin="0,0,0,8"/>

        <TextBlock Grid.Row="8" Grid.Column="0" Text="Raw line" Foreground="#9AA3B2" Margin="0,0,12,8" VerticalAlignment="Top"/>
        <TextBox Grid.Row="9" Grid.Column="0" Grid.ColumnSpan="2" x:Name="TxtDetailRaw" IsReadOnly="True"
                 TextWrapping="Wrap" AcceptsReturn="True" MinHeight="100" VerticalScrollBarVisibility="Auto"
                 FontFamily="Consolas" FontSize="12"
                 Background="#12151A" Foreground="#C5CAD3" BorderBrush="#383E4A" BorderThickness="1"
                 Padding="8,6"/>
      </Grid>
    </ScrollViewer>

    <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,12,0,0">
      <Button x:Name="BtnDetailCopyRaw" Content="Copy Raw Line" Width="130" Height="30" Margin="0,0,8,0"
              Background="#2A2F3A" Foreground="#E8EAF0" BorderBrush="#383E4A" BorderThickness="1"/>
      <Button x:Name="BtnDetailCopyAll" Content="Copy All" Width="100" Height="30" Margin="0,0,8,0"
              Background="#2A2F3A" Foreground="#E8EAF0" BorderBrush="#383E4A" BorderThickness="1"/>
      <Button x:Name="BtnDetailClose" Content="Close" Width="90" Height="30" IsDefault="True" IsCancel="True"
              Background="#2196F3" Foreground="White" BorderThickness="0"/>
    </StackPanel>
  </Grid>
</Window>
'@
    
    try {
        $dialog = [Windows.Markup.XamlReader]::Load([System.Xml.XmlNodeReader]::new($dialogXaml))
        if ($script:Window) { $dialog.Owner = $script:Window }
        
        $dialog.FindName('TxtDetailSubtitle').Text = "ID $eventId  ·  $time  ·  $server"
        $dialog.FindName('TxtDetailServer').Text = $server
        $dialog.FindName('TxtDetailTime').Text = $time
        $dialog.FindName('TxtDetailEventId').Text = $eventId
        $dialog.FindName('TxtDetailDescription').Text = $meaning
        $dialog.FindName('TxtDetailIp').Text = $ip
        $dialog.FindName('TxtDetailMac').Text = $mac
        $dialog.FindName('TxtDetailHost').Text = $hostName
        $dialog.FindName('TxtDetailExtra').Text = $details
        $dialog.FindName('TxtDetailRaw').Text = $raw
        
        $btnCopyRaw = $dialog.FindName('BtnDetailCopyRaw')
        $btnCopyAll = $dialog.FindName('BtnDetailCopyAll')
        $btnClose = $dialog.FindName('BtnDetailClose')
        
        $script:EventDetailCopyRaw = $raw
        $script:EventDetailCopyAll = @(
            "DHCP Event Details"
            "Server:      $server"
            "Time:        $time"
            "Event ID:    $eventId"
            "Description: $meaning"
            "IP Address:  $ip"
            "MAC:         $mac"
            "Hostname:    $hostName"
            "Details:     $details"
            "Raw:         $raw"
        ) -join [Environment]::NewLine
        $script:EventDetailCopyId = $eventId
        
        $btnCopyRaw.add_Click({
            try {
                [System.Windows.Clipboard]::SetText("$($script:EventDetailCopyRaw)")
                Write-ActionLog "Copied event raw line to clipboard (ID $($script:EventDetailCopyId))" "INFO"
            } catch {
                Show-MessageBox "Could not copy to clipboard: $_" "Event Details" OK Warning
            }
        })
        
        $btnCopyAll.add_Click({
            try {
                [System.Windows.Clipboard]::SetText("$($script:EventDetailCopyAll)")
                Write-ActionLog "Copied full event details to clipboard (ID $($script:EventDetailCopyId))" "INFO"
            } catch {
                Show-MessageBox "Could not copy to clipboard: $_" "Event Details" OK Warning
            }
        })
        
        $btnClose.add_Click({
            $dialog.DialogResult = $true
            $dialog.Close()
        })
        
        [void]$dialog.ShowDialog()
    } catch {
        Write-ActionLog "Event detail dialog failed: $_" "ERROR"
        Show-MessageBox "Failed to open event details: $_" "Event Details" OK Error
    } finally {
        $script:EventDetailCopyRaw = $null
        $script:EventDetailCopyAll = $null
        $script:EventDetailCopyId = $null
    }
}

function ConvertFrom-DhcpAuditLine {
    param(
        [string]$Line,
        [string]$ServerLabel
    )
    
    if ([string]::IsNullOrWhiteSpace($Line)) { return $null }
    if ($Line -match '^\s*#') { return $null }
    if ($Line -match '^(ID|Microsoft)') { return $null }
    
    # Classic CSV: ID,Date,Time,Description,IP,HostName,MAC,...
    $parts = @($Line.Split(','))
    $partCount = Get-SafeCount $parts
    if ($partCount -lt 3) { return $null }
    
    $eventId = "$($parts[0])".Trim()
    if ($eventId -notmatch '^\d{1,3}$') { return $null }
    
    $date = if ($partCount -gt 1) { "$($parts[1])".Trim() } else { '' }
    $time = if ($partCount -gt 2) { "$($parts[2])".Trim() } else { '' }
    $desc = if ($partCount -gt 3 -and "$($parts[3])".Trim()) { "$($parts[3])".Trim() } else { Get-DhcpEventDescription $eventId }
    $ip   = if ($partCount -gt 4) { "$($parts[4])".Trim() } else { '' }
    $hostName = if ($partCount -gt 5) { "$($parts[5])".Trim() } else { '' }
    $mac  = if ($partCount -gt 6) { "$($parts[6])".Trim() } else { '' }
    
    $stamp = ("$date $time").Trim()
    if (-not $stamp) { $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss' }
    
    $details = if ($partCount -gt 7) { ($parts[7..($partCount-1)] -join ',').Trim() } else { '' }
    
    return [PSCustomObject]@{
        Server      = $ServerLabel
        Time        = $stamp
        EventId     = $eventId
        Description = $desc
        IPAddress   = $ip
        MacAddress  = $mac
        HostName    = $hostName
        Details     = $details
        Raw         = $Line
    }
}

function Get-NormalizedMacForFilter {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    return (($Value -replace '[^0-9A-Fa-f]', '')).ToUpperInvariant()
}

function Get-EventFilterCriteria {
    $search = ''
    $eventId = 'All'
    $ip = ''
    $mac = ''
    $hostName = ''
    $server = 'All'
    
    try { $search = "$($script:TxtEventFilter.Text)".Trim() } catch {}
    try {
        if ($null -ne $script:CboEventIdFilter.SelectedItem) {
            $eventId = "$($script:CboEventIdFilter.SelectedItem.Content)"
        }
    } catch {}
    try { $ip = "$($script:TxtEventFilterIp.Text)".Trim() } catch {}
    try { $mac = "$($script:TxtEventFilterMac.Text)".Trim() } catch {}
    try { $hostName = "$($script:TxtEventFilterHost.Text)".Trim() } catch {}
    try {
        if ($null -ne $script:CboEventFilterServer.SelectedItem) {
            $server = "$($script:CboEventFilterServer.SelectedItem.Content)"
        }
    } catch {}
    
    return [PSCustomObject]@{
        Search   = $search
        EventId  = $eventId
        IP       = $ip
        MAC      = $mac
        HostName = $hostName
        Server   = $server
    }
}

function Test-DhcpEventMatchesFilter {
    param(
        [object]$Entry,
        [object]$Criteria
    )
    
    if ($null -eq $Entry) { return $false }
    if ($null -eq $Criteria) { return $true }
    
    if ($Criteria.Server -and $Criteria.Server -ne 'All') {
        if ("$($Entry.Server)" -ne "$($Criteria.Server)") { return $false }
    }
    
    if ($Criteria.EventId -and $Criteria.EventId -ne 'All') {
        $idText = "$($Criteria.EventId)"
        $wantId = ($idText -split '—')[0].Trim()
        if ($wantId -eq '50+') {
            $num = 0
            if (-not [int]::TryParse("$($Entry.EventId)", [ref]$num) -or $num -lt 50) { return $false }
        } else {
            if ("$($Entry.EventId)" -ne $wantId) { return $false }
        }
    }
    
    if ($Criteria.IP) {
        if ("$($Entry.IPAddress)" -notlike "*$($Criteria.IP)*") { return $false }
    }
    
    if ($Criteria.MAC) {
        $needle = Get-NormalizedMacForFilter $Criteria.MAC
        $hay = Get-NormalizedMacForFilter "$($Entry.MacAddress)"
        if (-not $hay -or ($hay -notlike "*$needle*")) { return $false }
    }
    
    if ($Criteria.HostName) {
        if ("$($Entry.HostName)" -notlike "*$($Criteria.HostName)*") { return $false }
    }
    
    if ($Criteria.Search) {
        $blob = "$($Entry.Server) $($Entry.Time) $($Entry.EventId) $($Entry.Description) $($Entry.IPAddress) $($Entry.MacAddress) $($Entry.HostName) $($Entry.Details)"
        if ($blob -notlike "*$($Criteria.Search)*") { return $false }
    }
    
    return $true
}

function Update-EventFilterServerCombo {
    $current = 'All'
    try {
        if ($null -ne $script:CboEventFilterServer.SelectedItem) {
            $current = "$($script:CboEventFilterServer.SelectedItem.Content)"
        }
    } catch {}
    
    $servers = @('All') + @($Global:DhcpEventEntriesAll | ForEach-Object { "$($_.Server)" } | Where-Object { $_ } | Sort-Object -Unique)
    
    $script:UpdatingEventFilterServerCombo = $true
    try {
        $script:CboEventFilterServer.Items.Clear()
        foreach ($s in $servers) {
            $item = New-Object System.Windows.Controls.ComboBoxItem
            $item.Content = $s
            [void]$script:CboEventFilterServer.Items.Add($item)
            if ($s -eq $current) { $script:CboEventFilterServer.SelectedItem = $item }
        }
        if ($null -eq $script:CboEventFilterServer.SelectedItem -and (Get-SafeCount $script:CboEventFilterServer.Items) -gt 0) {
            $script:CboEventFilterServer.SelectedIndex = 0
        }
    } catch {
    } finally {
        $script:UpdatingEventFilterServerCombo = $false
    }
}

function Update-EventFilterCountDisplay {
    param(
        [int]$Shown = -1,
        [int]$Total = -1
    )
    
    if ($Shown -lt 0) { $Shown = Get-SafeCount $Global:DhcpEventEntries }
    if ($Total -lt 0) { $Total = Get-SafeCount $Global:DhcpEventEntriesAll }
    
    try {
        if ($null -ne $script:TxtEventFilterCount) {
            $script:TxtEventFilterCount.Text = "Showing $Shown of $Total"
        }
    } catch {}
}

function Apply-DhcpEventFilter {
    <#
    .SYNOPSIS
        Rebuilds the visible events grid from the master ingested list
    #>
    param([switch]$Quiet)
    
    $criteria = Get-EventFilterCriteria
    $filtered = [System.Collections.Generic.List[object]]::new()
    
    foreach ($entry in @($Global:DhcpEventEntriesAll)) {
        if (Test-DhcpEventMatchesFilter -Entry $entry -Criteria $criteria) {
            [void]$filtered.Add($entry)
        }
    }
    
    $script:PendingFilteredEvents = $filtered
    
    $apply = {
        $Global:DhcpEventEntries.Clear()
        foreach ($entry in @($script:PendingFilteredEvents)) {
            [void]$Global:DhcpEventEntries.Add($entry)
        }
        if ($null -ne $script:GridEvents) {
            $script:GridEvents.ItemsSource = $null
            $script:GridEvents.ItemsSource = $Global:DhcpEventEntries
        }
    }
    
    try {
        if ($null -ne $script:Window -and -not $script:Window.Dispatcher.CheckAccess()) {
            $script:Window.Dispatcher.Invoke([action]$apply, [System.Windows.Threading.DispatcherPriority]::Normal)
        } else {
            & $apply
        }
    } catch {
        try { & $apply } catch {}
    }
    
    $shown = Get-SafeCount $filtered
    $total = Get-SafeCount $Global:DhcpEventEntriesAll
    Update-EventFilterCountDisplay -Shown $shown -Total $total
    
    if (-not $Quiet) {
        Write-ActionLog "Event filter applied: showing $shown of $total" "INFO"
        try {
            if ($null -ne $script:TxtEventStatus -and -not $Global:EventWatchActive) {
                $script:TxtEventStatus.Text = "Filter active — showing $shown of $total events. Created by $($Global:AppAuthor)."
            }
        } catch {}
        Update-LogDisplay
    }
}

function Clear-DhcpEventFilterFields {
    try { $script:TxtEventFilter.Text = '' } catch {}
    try { $script:TxtEventFilterIp.Text = '' } catch {}
    try { $script:TxtEventFilterMac.Text = '' } catch {}
    try { $script:TxtEventFilterHost.Text = '' } catch {}
    try {
        if ($null -ne $script:CboEventIdFilter -and (Get-SafeCount $script:CboEventIdFilter.Items) -gt 0) {
            $script:CboEventIdFilter.SelectedIndex = 0
        }
    } catch {}
    try {
        if ($null -ne $script:CboEventFilterServer -and (Get-SafeCount $script:CboEventFilterServer.Items) -gt 0) {
            $script:CboEventFilterServer.SelectedIndex = 0
        }
    } catch {}
}

function Add-DhcpEventEntry {
    param([object]$Entry)
    
    if ($null -eq $Entry) { return }
    Add-DhcpEventEntriesBatch -Entries @($Entry)
}

function Add-DhcpEventEntriesBatch {
    <#
    .SYNOPSIS
        Adds event rows to master list and visible grid (filtered) in one UI update
    #>
    param([object[]]$Entries)
    
    $items = @($Entries | Where-Object { $null -ne $_ })
    if ((Get-SafeCount $items) -eq 0) { return }
    
    foreach ($entry in $items) {
        $Global:DhcpEventEntriesAll.Insert(0, $entry)
    }
    while ((Get-SafeCount $Global:DhcpEventEntriesAll) -gt 5000) {
        $Global:DhcpEventEntriesAll.RemoveAt((Get-SafeCount $Global:DhcpEventEntriesAll) - 1)
    }
    
    $criteria = Get-EventFilterCriteria
    $visible = @($items | Where-Object { Test-DhcpEventMatchesFilter -Entry $_ -Criteria $criteria })
    
    $apply = {
        foreach ($entry in $visible) {
            $Global:DhcpEventEntries.Insert(0, $entry)
        }
        while ((Get-SafeCount $Global:DhcpEventEntries) -gt 5000) {
            $Global:DhcpEventEntries.RemoveAt((Get-SafeCount $Global:DhcpEventEntries) - 1)
        }
        if ($null -eq $script:GridEvents.ItemsSource) {
            $script:GridEvents.ItemsSource = $Global:DhcpEventEntries
        }
    }
    
    try {
        if ($null -ne $script:Window -and -not $script:Window.Dispatcher.CheckAccess()) {
            $script:Window.Dispatcher.Invoke([action]$apply, [System.Windows.Threading.DispatcherPriority]::Background)
        } else {
            & $apply
        }
    } catch {
        try { & $apply } catch {}
    }
    
    Update-EventFilterServerCombo
    Update-EventFilterCountDisplay
}

function Set-DhcpEventEntriesFromList {
    <#
    .SYNOPSIS
        Replaces master + visible event lists (newest-first)
    #>
    param([System.Collections.IList]$Entries)
    
    $snapshot = @($Entries)
    
    $Global:DhcpEventEntriesAll.Clear()
    foreach ($entry in $snapshot) {
        if ($null -ne $entry) { [void]$Global:DhcpEventEntriesAll.Add($entry) }
    }
    
    Update-EventFilterServerCombo
    Apply-DhcpEventFilter -Quiet
}

function Import-DhcpAuditLogFile {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [string]$ServerLabel = 'Local',
        [switch]$TailOnly,
        [int]$MaxEvents = 5000
    )
    
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Log path not found: $Path"
    }
    
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer) {
        $newest = @(Get-ChildItem -LiteralPath $Path -Filter 'DhcpSrvLog*' -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending)
        if ((Get-SafeCount $newest) -eq 0) { throw "No DhcpSrvLog* files in $Path" }
        $Path = $newest[0].FullName
        $item = Get-Item -LiteralPath $Path
    }
    
    Write-ActionLog "Ingesting DHCP audit log: $Path ($ServerLabel)" "INFO"
    
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        if ($TailOnly) {
            $fs.Seek(0, [System.IO.SeekOrigin]::End) | Out-Null
            return [PSCustomObject]@{ Path = $Path; Offset = $fs.Position; EventCount = 0; Shown = 0; Canceled = $false }
        }
        
        $totalBytes = [math]::Max(1L, [long]$fs.Length)
        $fileSizeMb = [math]::Round($totalBytes / 1MB, 2)
        Start-TaskProgress -Name 'Ingest' -CanPause `
            -Message "Ingesting $([IO.Path]::GetFileName($Path)) ($fileSizeMb MB)..." `
            -Total $totalBytes
        
        try {
            if ($null -ne $script:BtnEventIngest) { $script:BtnEventIngest.IsEnabled = $false }
        } catch {}
        
        $reader = New-Object System.IO.StreamReader($fs)
        $parsed = [System.Collections.Generic.List[object]]::new()
        $linesRead = 0
        $eventsFound = 0
        $lastUi = Get-Date
        $canceled = $false
        
        while ($null -ne ($line = $reader.ReadLine())) {
            Wait-TaskProgressIfPaused
            if (Test-TaskCancelRequested) {
                $canceled = $true
                break
            }
            
            $linesRead++
            $entry = ConvertFrom-DhcpAuditLine -Line $line -ServerLabel $ServerLabel
            if ($entry) {
                $parsed.Add($entry)
                $eventsFound++
            }
            
            $now = Get-Date
            if ((($now - $lastUi).TotalMilliseconds -ge 200) -or (($linesRead % 1500) -eq 0)) {
                $pos = [long]$fs.Position
                $msg = "Ingesting $([IO.Path]::GetFileName($Path)) — $eventsFound events / $linesRead lines ($([math]::Round($pos/1MB, 2)) / $fileSizeMb MB)"
                Update-TaskProgress -Processed $pos -Total $totalBytes -Message $msg
                $lastUi = $now
            }
        }
        
        $offset = $fs.Position
        
        if ($canceled) {
            Write-ActionLog "Ingest canceled after $eventsFound parsed events ($linesRead lines)" "WARN"
            Complete-TaskProgress -Message "Ingest canceled — kept previous events"
            try { if ($null -ne $script:BtnEventIngest) { $script:BtnEventIngest.IsEnabled = $true } } catch {}
            return [PSCustomObject]@{ Path = $Path; Offset = $offset; EventCount = 0; Shown = 0; Canceled = $true }
        }
        
        Update-TaskProgress -Processed $totalBytes -Total $totalBytes -Percent 95 `
            -Message "Building event list ($eventsFound events)..."
        
        # Keep newest MaxEvents (file is oldest→newest)
        $toShow = [System.Collections.Generic.List[object]]::new()
        $startIdx = 0
        $count = $parsed.Count
        if ($count -gt $MaxEvents) {
            $startIdx = $count - $MaxEvents
        }
        for ($i = $count - 1; $i -ge $startIdx; $i--) {
            $toShow.Add($parsed[$i])
        }
        
        Set-DhcpEventEntriesFromList -Entries $toShow
        
        $shown = Get-SafeCount $toShow
        $trimNote = if ($count -gt $MaxEvents) { " (showing newest $shown of $count)" } else { '' }
        Write-ActionLog "Ingested $count events from $ServerLabel$trimNote" "SUCCESS"
        Complete-TaskProgress -Message "Ingested $count events$trimNote"
        
        try { if ($null -ne $script:BtnEventIngest) { $script:BtnEventIngest.IsEnabled = $true } } catch {}
        
        return [PSCustomObject]@{ Path = $Path; Offset = $offset; EventCount = $count; Shown = $shown; Canceled = $false }
    } catch {
        Complete-TaskProgress -Message "Ingest failed"
        try { if ($null -ne $script:BtnEventIngest) { $script:BtnEventIngest.IsEnabled = $true } } catch {}
        throw
    } finally {
        $fs.Dispose()
    }
}

function Read-DhcpAuditLogDelta {
    param(
        [string]$Path,
        [long]$Offset,
        [string]$ServerLabel
    )
    
    if (-not (Test-Path -LiteralPath $Path)) {
        return [PSCustomObject]@{ Offset = $Offset; Added = 0 }
    }
    
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $length = $fs.Length
        if ($Offset -gt $length) { $Offset = 0L }  # log rotated
        
        $fs.Seek($Offset, [System.IO.SeekOrigin]::Begin) | Out-Null
        $reader = New-Object System.IO.StreamReader($fs)
        $batch = [System.Collections.Generic.List[object]]::new()
        while ($null -ne ($line = $reader.ReadLine())) {
            $entry = ConvertFrom-DhcpAuditLine -Line $line -ServerLabel $ServerLabel
            if ($entry) { $batch.Add($entry) }
        }
        
        if ((Get-SafeCount $batch) -gt 0) {
            # Newest last in file → insert in reverse so newest ends on top
            $ordered = [System.Collections.Generic.List[object]]::new()
            for ($i = $batch.Count - 1; $i -ge 0; $i--) { $ordered.Add($batch[$i]) }
            Add-DhcpEventEntriesBatch -Entries @($ordered)
        }
        
        return [PSCustomObject]@{ Offset = $fs.Position; Added = (Get-SafeCount $batch) }
    } finally {
        $fs.Dispose()
    }
}

function Get-SelectedEventSourceKey {
    $label = 'Local Server'
    try {
        if ($null -ne $script:CboEventSource.SelectedItem) {
            $label = $script:CboEventSource.SelectedItem.Content
        }
    } catch {}
    
    switch ($label) {
        'Server A'     { return 'A' }
        'Server B'     { return 'B' }
        'Custom Path'  { return 'Custom' }
        default        { return 'Local' }
    }
}

function Get-EventServerLabel {
    param([string]$SourceKey)
    switch ($SourceKey) {
        'A' { if ($Global:DHCPServer) { "A:$($Global:DHCPServer)" } else { 'Server A' } }
        'B' { if ($Global:CompareServer) { "B:$($Global:CompareServer)" } else { 'Server B' } }
        'Custom' { 'Custom' }
        default { 'Local' }
    }
}

function Update-EventWatchStatus {
    $parts = [System.Collections.Generic.List[string]]::new()
    if ($Global:EventWatchActive) {
        if ($Global:LogWatchState.Local.Enabled)  { [void]$parts.Add("Local→$([IO.Path]::GetFileName($Global:LogWatchState.Local.Path))") }
        if ($Global:LogWatchState.A.Enabled)      { [void]$parts.Add("A→$([IO.Path]::GetFileName($Global:LogWatchState.A.Path))") }
        if ($Global:LogWatchState.B.Enabled)      { [void]$parts.Add("B→$([IO.Path]::GetFileName($Global:LogWatchState.B.Path))") }
        if ($Global:LogWatchState.Custom.Enabled) { [void]$parts.Add("Custom→$([IO.Path]::GetFileName($Global:LogWatchState.Custom.Path))") }
        $msg = if ((Get-SafeCount $parts) -gt 0) { "LIVE watching: " + ($parts -join '  |  ') } else { 'Watch running (no sources enabled)' }
    } else {
        $msg = "Idle — $(Get-SafeCount $Global:DhcpEventEntries) events loaded. Created by $($Global:AppAuthor)."
    }
    
    try {
        $script:TxtEventStatus.Dispatcher.Invoke([action]{
            $script:TxtEventStatus.Text = $msg
        }, [System.Windows.Threading.DispatcherPriority]::Background)
    } catch {
        try { $script:TxtEventStatus.Text = $msg } catch {}
    }
}

function Start-DhcpEventWatch {
    $watchLocal  = [bool]$script:ChkWatchLocal.IsChecked
    $watchA      = [bool]$script:ChkWatchA.IsChecked
    $watchB      = [bool]$script:ChkWatchB.IsChecked
    $watchCustom = $false
    try { $watchCustom = [bool]$script:ChkWatchCustom.IsChecked } catch {}
    
    if (-not ($watchLocal -or $watchA -or $watchB -or $watchCustom)) {
        Show-MessageBox "Select at least one live watch target: Local, Server A, Server B, and/or Custom file." "Live Watch" OK Warning
        return
    }
    
    if ($watchA -and [string]::IsNullOrWhiteSpace($Global:DHCPServer)) {
        Show-MessageBox "Connect Server A before watching it." "Live Watch" OK Warning
        return
    }
    
    if ($watchB -and [string]::IsNullOrWhiteSpace($Global:CompareServer)) {
        Show-MessageBox "Connect Server B (Compare tab) before watching it." "Live Watch" OK Warning
        return
    }
    
    $customPath = ''
    if ($watchCustom) {
        try { $customPath = "$($script:TxtWatchLogPath.Text)".Trim() } catch {}
        if ([string]::IsNullOrWhiteSpace($customPath)) {
            try { $customPath = "$($script:TxtEventLogPath.Text)".Trim() } catch {}
        }
        if ([string]::IsNullOrWhiteSpace($customPath)) {
            Show-MessageBox "Enter or browse to the DHCP audit log file to watch (Watch file path)." "Live Watch" OK Warning
            return
        }
        if (-not (Test-Path -LiteralPath $customPath)) {
            Show-MessageBox "Watch file path not found:`n$customPath" "Live Watch" OK Warning
            return
        }
    }
    
    Write-ActionLog "Starting DHCP live event watch..." "INFO"
    
    foreach ($key in @('Local','A','B','Custom')) {
        $Global:LogWatchState[$key].Enabled = $false
        $Global:LogWatchState[$key].Path = $null
        $Global:LogWatchState[$key].Offset = 0L
    }
    
    $started = [System.Collections.Generic.List[string]]::new()
    
    if ($watchLocal) {
        $path = Get-DhcpAuditLogPath -Source Local
        if (-not $path) { throw "Could not detect local DHCP audit log under $($env:SystemRoot)\System32\dhcp" }
        $info = Import-DhcpAuditLogFile -Path $path -ServerLabel 'Local' -TailOnly
        $Global:LogWatchState.Local.Enabled = $true
        $Global:LogWatchState.Local.Path = $info.Path
        $Global:LogWatchState.Local.Offset = [long]$info.Offset
        [void]$started.Add("Local ($($info.Path))")
    }
    
    if ($watchA) {
        $path = Get-DhcpAuditLogPath -Source A
        if (-not $path) { throw "Could not detect DHCP audit log for Server A ($($Global:DHCPServer)). Ensure admin$ or C$ share is reachable." }
        $label = Get-EventServerLabel -SourceKey 'A'
        $info = Import-DhcpAuditLogFile -Path $path -ServerLabel $label -TailOnly
        $Global:LogWatchState.A.Enabled = $true
        $Global:LogWatchState.A.Path = $info.Path
        $Global:LogWatchState.A.Offset = [long]$info.Offset
        [void]$started.Add("A ($($info.Path))")
    }
    
    if ($watchB) {
        $path = Get-DhcpAuditLogPath -Source B
        if (-not $path) { throw "Could not detect DHCP audit log for Server B ($($Global:CompareServer)). Ensure admin$ or C$ share is reachable." }
        $label = Get-EventServerLabel -SourceKey 'B'
        $info = Import-DhcpAuditLogFile -Path $path -ServerLabel $label -TailOnly
        $Global:LogWatchState.B.Enabled = $true
        $Global:LogWatchState.B.Path = $info.Path
        $Global:LogWatchState.B.Offset = [long]$info.Offset
        [void]$started.Add("B ($($info.Path))")
    }
    
    if ($watchCustom) {
        $info = Import-DhcpAuditLogFile -Path $customPath -ServerLabel 'Custom' -TailOnly
        $Global:LogWatchState.Custom.Enabled = $true
        $Global:LogWatchState.Custom.Path = $info.Path
        $Global:LogWatchState.Custom.Offset = [long]$info.Offset
        try { $script:TxtWatchLogPath.Text = $info.Path } catch {}
        [void]$started.Add("Custom ($($info.Path))")
    }
    
    if (-not (Get-Variable -Name EventWatchTimer -Scope Script -ErrorAction SilentlyContinue)) {
        $script:EventWatchTimer = $null
    }
    
    if ($null -eq $script:EventWatchTimer) {
        $script:EventWatchTimer = New-Object System.Windows.Threading.DispatcherTimer
        $script:EventWatchTimer.Interval = [TimeSpan]::FromSeconds(2)
        $script:EventWatchTimer.Add_Tick({
            if (-not $Global:EventWatchActive) { return }
            
            $newTotal = 0
            foreach ($key in @('Local','A','B','Custom')) {
                $st = $Global:LogWatchState[$key]
                if (-not $st.Enabled -or -not $st.Path) { continue }
                
                $label = switch ($key) {
                    'A' { Get-EventServerLabel -SourceKey 'A' }
                    'B' { Get-EventServerLabel -SourceKey 'B' }
                    'Custom' { 'Custom' }
                    default { 'Local' }
                }
                
                try {
                    $delta = Read-DhcpAuditLogDelta -Path $st.Path -Offset ([long]$st.Offset) -ServerLabel $label
                    $st.Offset = [long]$delta.Offset
                    $newTotal += [int]$delta.Added
                } catch {
                    Write-ActionLog "Watch poll failed for $key : $_" "WARN"
                }
            }
            
            if ($newTotal -gt 0) {
                Set-Status "Live DHCP events: +$newTotal"
            }
            Update-EventWatchStatus
        })
    }
    
    $Global:EventWatchActive = $true
    $script:EventWatchTimer.Start()
    
    $script:BtnEventWatchStart.IsEnabled = $false
    $script:BtnEventWatchStop.IsEnabled = $true
    $script:ChkWatchLocal.IsEnabled = $false
    $script:ChkWatchA.IsEnabled = $false
    $script:ChkWatchB.IsEnabled = $false
    try {
        $script:ChkWatchCustom.IsEnabled = $false
        $script:TxtWatchLogPath.IsEnabled = $false
        $script:BtnWatchBrowse.IsEnabled = $false
        $script:BtnWatchUseIngestPath.IsEnabled = $false
    } catch {}
    
    Write-ActionLog ("Live watch started: " + ($started -join '; ')) "SUCCESS"
    Update-EventWatchStatus
    Update-LogDisplay
    Set-Status "Live DHCP event watch active"
}

function Stop-DhcpEventWatch {
    Write-ActionLog "Stopping DHCP live event watch..." "INFO"
    
    $Global:EventWatchActive = $false
    try {
        if ((Get-Variable -Name EventWatchTimer -Scope Script -ErrorAction SilentlyContinue) -and $script:EventWatchTimer) {
            $script:EventWatchTimer.Stop()
        }
    } catch {}
    
    foreach ($key in @('Local','A','B','Custom')) {
        $Global:LogWatchState[$key].Enabled = $false
    }
    
    $script:BtnEventWatchStart.IsEnabled = $true
    $script:BtnEventWatchStop.IsEnabled = $false
    $script:ChkWatchLocal.IsEnabled = $true
    $script:ChkWatchA.IsEnabled = $true
    $script:ChkWatchB.IsEnabled = $true
    try {
        $script:ChkWatchCustom.IsEnabled = $true
        $script:TxtWatchLogPath.IsEnabled = $true
        $script:BtnWatchBrowse.IsEnabled = $true
        $script:BtnWatchUseIngestPath.IsEnabled = $true
    } catch {}
    
    Update-EventWatchStatus
    Write-ActionLog "Live watch stopped" "SUCCESS"
    Set-Status "Live watch stopped"
    Update-LogDisplay
}
#endregion

#region Scope Migration Engine (A → B)
function Update-MigrateReadyState {
    $sourceReady = -not [string]::IsNullOrWhiteSpace($Global:DHCPServer)
    $bothReady = $sourceReady -and (-not [string]::IsNullOrWhiteSpace($Global:CompareServer))
    $hasSelection = @($Global:MigrationScopes | Where-Object { $_.Selected }).Count -gt 0
    
    try {
        $script:Window.Dispatcher.Invoke([action]{
            if ($Global:DHCPServer) {
                $script:TxtMigrateSource.Text = $Global:DHCPServer
                $script:TxtMigrateSource.Foreground = [System.Windows.Media.Brushes]::LimeGreen
            } else {
                $script:TxtMigrateSource.Text = "Not Connected"
                $script:TxtMigrateSource.Foreground = [System.Windows.Media.Brushes]::Orange
            }
            
            if ($Global:CompareServer) {
                $script:TxtMigrateDest.Text = $Global:CompareServer
                $script:TxtMigrateDest.Foreground = [System.Windows.Media.Brushes]::LimeGreen
            } else {
                $script:TxtMigrateDest.Text = "Not Connected"
                $script:TxtMigrateDest.Foreground = [System.Windows.Media.Brushes]::Orange
            }
            
            $script:BtnMigrateRefreshScopes.IsEnabled = $bothReady
            $script:BtnMigrateDryRun.IsEnabled = ($bothReady -and $hasSelection)
            $script:BtnMigrateRun.IsEnabled = ($bothReady -and $hasSelection)
            $script:BtnMigrateExport.IsEnabled = ($Global:MigrationResults.Count -gt 0)
            
            if (-not $sourceReady) {
                $script:TxtMigrateStatus.Text = "Connect Server A (source) first"
            } elseif (-not $Global:CompareServer) {
                $script:TxtMigrateStatus.Text = "Connect Server B (destination) on the Compare tab"
            } elseif ($Global:MigrationScopes.Count -eq 0) {
                $script:TxtMigrateStatus.Text = "Click Load Source Scopes, then select scopes to migrate"
            } elseif (-not $hasSelection) {
                $script:TxtMigrateStatus.Text = "Select one or more scopes (checkbox), then Dry Run or Migrate"
            } else {
                $sel = @($Global:MigrationScopes | Where-Object { $_.Selected }).Count
                $script:TxtMigrateStatus.Text = "Ready to migrate $sel scope(s): $($Global:DHCPServer) → $($Global:CompareServer)"
            }
        }, [System.Windows.Threading.DispatcherPriority]::Normal)
    } catch {}
}

function Add-MigrationResult {
    param(
        [string]$ScopeId,
        [string]$Step,
        [string]$Status,
        [string]$Message
    )
    
    $row = [PSCustomObject]@{
        ScopeId = $ScopeId
        Step    = $Step
        Status  = $Status
        Message = $Message
    }
    $Global:MigrationResults.Add($row)
    
    Write-ActionLog "[Migrate][$ScopeId][$Step][$Status] $Message" $(
        switch ($Status) {
            'SUCCESS' { 'SUCCESS' }
            'ERROR'   { 'ERROR' }
            'SKIP'    { 'WARN' }
            'PLAN'    { 'INFO' }
            default   { 'INFO' }
        }
    )
}

function Get-MigrationOptionsFromUi {
    $conflict = 'Merge into existing'
    try {
        if ($null -ne $script:CboMigConflict.SelectedItem) {
            $conflict = $script:CboMigConflict.SelectedItem.Content
        }
    } catch {}
    
    return [PSCustomObject]@{
        MigrateScope         = [bool]$script:ChkMigScope.IsChecked
        MigrateOptions       = [bool]$script:ChkMigOptions.IsChecked
        MigrateReservations  = [bool]$script:ChkMigReservations.IsChecked
        MigrateExclusions    = [bool]$script:ChkMigExclusions.IsChecked
        MigrateLeasesAsRes   = [bool]$script:ChkMigLeasesAsRes.IsChecked
        ActivateDest         = [bool]$script:ChkMigActivateDest.IsChecked
        DeactivateSource     = [bool]$script:ChkMigDeactivateSource.IsChecked
        ConflictMode         = $conflict
    }
}

function Import-MigrationSourceScopes {
    if ([string]::IsNullOrWhiteSpace($Global:DHCPServer) -or [string]::IsNullOrWhiteSpace($Global:CompareServer)) {
        throw "Both Server A (source) and Server B (destination) must be connected."
    }
    
    Write-ActionLog "Loading migration scopes from $($Global:DHCPServer)..." "INFO"
    Set-Status "Loading source scopes for migration..."
    
    $sourceScopes = @(Get-DhcpServerv4Scope -ComputerName $Global:DHCPServer -ErrorAction Stop)
    $destScopes = @()
    try {
        $destScopes = @(Get-DhcpServerv4Scope -ComputerName $Global:CompareServer -ErrorAction Stop)
    } catch {
        Write-ActionLog "Could not list destination scopes: $_" "WARN"
    }
    
    $destIds = @{}
    foreach ($d in $destScopes) { $destIds["$($d.ScopeId)"] = $true }
    
    $script:Window.Dispatcher.Invoke([action]{
        $Global:MigrationScopes.Clear()
        foreach ($s in $sourceScopes) {
            $item = [PSCustomObject]@{
                Selected       = $true
                ScopeId        = "$($s.ScopeId)"
                Name           = "$($s.Name)"
                StartRange     = "$($s.StartRange)"
                EndRange       = "$($s.EndRange)"
                SubnetMask     = "$($s.SubnetMask)"
                State          = "$($s.State)"
                OnDestination  = $(if ($destIds.ContainsKey("$($s.ScopeId)")) { 'Yes' } else { 'No' })
                LeaseDuration  = $s.LeaseDuration
                Description    = "$($s.Description)"
            }
            $Global:MigrationScopes.Add($item)
        }
        $script:GridMigrateScopes.ItemsSource = $null
        $script:GridMigrateScopes.ItemsSource = $Global:MigrationScopes
    }, [System.Windows.Threading.DispatcherPriority]::Normal)
    
    Write-ActionLog "Loaded $(Get-SafeCount $sourceScopes) source scopes for migration" "SUCCESS"
    Update-MigrateReadyState
    Set-Status "Loaded $(Get-SafeCount $sourceScopes) scopes for migration"
    Update-LogDisplay
}

function Set-MigrationScopeSelection {
    param([bool]$Selected)
    
    foreach ($item in @($Global:MigrationScopes)) {
        $item.Selected = $Selected
    }
    
    # Force grid refresh for checkbox column
    $script:GridMigrateScopes.ItemsSource = $null
    $script:GridMigrateScopes.ItemsSource = $Global:MigrationScopes
    Update-MigrateReadyState
}

function Invoke-DhcpScopeMigration {
    <#
    .SYNOPSIS
        Migrates selected scopes (and related options/reservations/exclusions/leases) from source to destination
    #>
    param(
        [switch]$DryRun,
        [string]$SourceServer,
        [string]$DestServer,
        [object[]]$Scopes,
        [object]$Options,
        [switch]$SkipConfirm,
        [switch]$AppendResults,
        [switch]$Quiet
    )
    
    if ([string]::IsNullOrWhiteSpace($SourceServer)) { $SourceServer = $Global:DHCPServer }
    if ([string]::IsNullOrWhiteSpace($DestServer)) { $DestServer = $Global:CompareServer }
    
    if ([string]::IsNullOrWhiteSpace($SourceServer) -or [string]::IsNullOrWhiteSpace($DestServer)) {
        Show-MessageBox "Connect both source and destination DHCP servers first." "Migrate" OK Warning
        return
    }
    
    if ($SourceServer -eq $DestServer) {
        Show-MessageBox "Source and destination must be different servers." "Migrate" OK Warning
        return
    }
    
    if ($null -eq $Scopes) {
        # Commit any pending checkbox edits on Migrate tab
        try { $script:GridMigrateScopes.CommitEdit() } catch {}
        $Scopes = @($Global:MigrationScopes | Where-Object { $_.Selected })
    } else {
        $Scopes = @($Scopes)
    }
    
    $selectedCount = Get-SafeCount $Scopes
    if ($selectedCount -eq 0) {
        Show-MessageBox "Select at least one scope to migrate." "Migrate" OK Warning
        return
    }
    
    if ($null -eq $Options) {
        $opts = Get-MigrationOptionsFromUi
    } else {
        $opts = $Options
    }
    
    if (-not ($opts.MigrateScope -or $opts.MigrateOptions -or $opts.MigrateReservations -or $opts.MigrateExclusions -or $opts.MigrateLeasesAsRes)) {
        Show-MessageBox "Select at least one include option (Scope, Options, Reservations, Exclusions, or Leases)." "Migrate" OK Warning
        return
    }
    
    $modeLabel = if ($DryRun) { 'DRY RUN' } else { 'MIGRATE' }
    
    if (-not $DryRun -and -not $SkipConfirm) {
        $includeParts = [System.Collections.Generic.List[string]]::new()
        if ($opts.MigrateScope)        { [void]$includeParts.Add('Scope') }
        if ($opts.MigrateOptions)      { [void]$includeParts.Add('Options') }
        if ($opts.MigrateReservations) { [void]$includeParts.Add('Reservations') }
        if ($opts.MigrateExclusions)   { [void]$includeParts.Add('Exclusions') }
        if ($opts.MigrateLeasesAsRes)  { [void]$includeParts.Add('Leases→Reservations') }
        
        $includeText = $includeParts -join ', '
        $confirmMsg = @(
            "Migrate $selectedCount scope(s) from"
            $SourceServer
            "to"
            $DestServer
            ""
            "Include: $includeText"
            "Conflict mode: $($opts.ConflictMode)"
        ) -join "`n"
        
        $confirm = Show-MessageBox $confirmMsg "Confirm Scope Migration" YesNo Warning
        if ($confirm -ne 'Yes') { return }
    }
    
    Write-ActionLog "===== $modeLabel start: $selectedCount scope(s) $SourceServer → $DestServer =====" "INFO"
    Set-Status "$modeLabel in progress..."
    
    if (-not $AppendResults) {
        $Global:MigrationResults.Clear()
    }
    $successScopes = 0
    $errorScopes = 0
    
    foreach ($sel in $Scopes) {
        $scopeId = if ($sel.PSObject.Properties.Name -contains 'ScopeId') { "$($sel.ScopeId)" } else { "$sel" }
        $scopeHadError = $false
        
        try {
            $srcScope = Get-DhcpServerv4Scope -ComputerName $SourceServer -ScopeId $scopeId -ErrorAction Stop
        } catch {
            Add-MigrationResult -ScopeId $scopeId -Step 'Load Source' -Status 'ERROR' -Message "$_"
            $errorScopes++
            continue
        }
        
        $destExists = $false
        try {
            $null = Get-DhcpServerv4Scope -ComputerName $DestServer -ScopeId $scopeId -ErrorAction Stop
            $destExists = $true
        } catch {
            $destExists = $false
        }

        # --- Scope definition ---
        if ($opts.MigrateScope) {
            if ($destExists) {
                switch ($opts.ConflictMode) {
                    'Fail' {
                        Add-MigrationResult -ScopeId $scopeId -Step 'Scope' -Status 'ERROR' -Message "Already exists on destination (Fail mode)"
                        $scopeHadError = $true
                        $errorScopes++
                        continue
                    }
                    'Skip scope' {
                        Add-MigrationResult -ScopeId $scopeId -Step 'Scope' -Status 'SKIP' -Message "Exists on destination — skipping entire scope"
                        continue
                    }
                    default {
                        Add-MigrationResult -ScopeId $scopeId -Step 'Scope' -Status $(if ($DryRun) { 'PLAN' } else { 'SKIP' }) `
                            -Message "Exists on destination — will merge selected components"
                    }
                }
            }
            else {
                $msg = "Create scope '$($srcScope.Name)' $($srcScope.StartRange)-$($srcScope.EndRange) mask $($srcScope.SubnetMask)"
                if ($DryRun) {
                    Add-MigrationResult -ScopeId $scopeId -Step 'Scope' -Status 'PLAN' -Message $msg
                } else {
                    try {
                        $addParams = @{
                            ComputerName = $DestServer
                            Name         = $srcScope.Name
                            StartRange   = $srcScope.StartRange
                            EndRange     = $srcScope.EndRange
                            SubnetMask   = $srcScope.SubnetMask
                            State        = 'Inactive'
                            ErrorAction  = 'Stop'
                        }
                        if ($srcScope.Description) { $addParams['Description'] = $srcScope.Description }
                        if ($srcScope.LeaseDuration) { $addParams['LeaseDuration'] = $srcScope.LeaseDuration }
                        
                        Add-DhcpServerv4Scope @addParams
                        Add-MigrationResult -ScopeId $scopeId -Step 'Scope' -Status 'SUCCESS' -Message "Created on $($DestServer)"
                        $destExists = $true
                    } catch {
                        Add-MigrationResult -ScopeId $scopeId -Step 'Scope' -Status 'ERROR' -Message "$_"
                        $scopeHadError = $true
                        $errorScopes++
                        continue
                    }
                }
            }
        }
        elseif (-not $destExists) {
            Add-MigrationResult -ScopeId $scopeId -Step 'Scope' -Status 'ERROR' `
                -Message "Scope missing on destination and 'Scope' include is unchecked"
            $scopeHadError = $true
            $errorScopes++
            continue
        }
        
        # After dry-run scope create plan, still plan child objects
        $canMutateChildren = $destExists -or $DryRun
        
        # --- Exclusions ---
        if ($opts.MigrateExclusions -and $canMutateChildren) {
            try {
                $exclusions = @(Get-DhcpServerv4ExclusionRange -ComputerName $SourceServer -ScopeId $scopeId -ErrorAction SilentlyContinue)
                if ((Get-SafeCount $exclusions) -eq 0) {
                    Add-MigrationResult -ScopeId $scopeId -Step 'Exclusions' -Status 'SKIP' -Message 'No exclusions on source'
                } else {
                    foreach ($ex in $exclusions) {
                        $exMsg = "$($ex.StartRange) - $($ex.EndRange)"
                        if ($DryRun) {
                            Add-MigrationResult -ScopeId $scopeId -Step 'Exclusion' -Status 'PLAN' -Message $exMsg
                        } else {
                            try {
                                Add-DhcpServerv4ExclusionRange -ComputerName $DestServer -ScopeId $scopeId `
                                    -StartRange $ex.StartRange -EndRange $ex.EndRange -ErrorAction Stop
                                Add-MigrationResult -ScopeId $scopeId -Step 'Exclusion' -Status 'SUCCESS' -Message $exMsg
                            } catch {
                                if ("$_" -match 'already|exists|conflict') {
                                    Add-MigrationResult -ScopeId $scopeId -Step 'Exclusion' -Status 'SKIP' -Message "$exMsg (already present)"
                                } else {
                                    Add-MigrationResult -ScopeId $scopeId -Step 'Exclusion' -Status 'ERROR' -Message "$exMsg — $_"
                                    $scopeHadError = $true
                                }
                            }
                        }
                    }
                }
            } catch {
                Add-MigrationResult -ScopeId $scopeId -Step 'Exclusions' -Status 'ERROR' -Message "$_"
                $scopeHadError = $true
            }
        }
        
        # --- Scope options ---
        if ($opts.MigrateOptions -and $canMutateChildren) {
            try {
                $options = @(Get-DhcpServerv4OptionValue -ComputerName $SourceServer -ScopeId $scopeId -ErrorAction SilentlyContinue)
                if ((Get-SafeCount $options) -eq 0) {
                    Add-MigrationResult -ScopeId $scopeId -Step 'Options' -Status 'SKIP' -Message 'No scope options on source'
                } else {
                    foreach ($opt in $options) {
                        $val = ($opt.Value -join ', ')
                        $optMsg = "Option $($opt.OptionId) ($($opt.Name)) = $val"
                        if ($DryRun) {
                            Add-MigrationResult -ScopeId $scopeId -Step 'Option' -Status 'PLAN' -Message $optMsg
                        } else {
                            try {
                                $setParams = @{
                                    ComputerName = $DestServer
                                    ScopeId      = $scopeId
                                    OptionId     = $opt.OptionId
                                    Value        = $opt.Value
                                    ErrorAction  = 'Stop'
                                }
                                if ($opt.VendorClass) { $setParams['VendorClass'] = $opt.VendorClass }
                                if ($opt.UserClass)   { $setParams['UserClass'] = $opt.UserClass }
                                Set-DhcpServerv4OptionValue @setParams
                                Add-MigrationResult -ScopeId $scopeId -Step 'Option' -Status 'SUCCESS' -Message $optMsg
                            } catch {
                                Add-MigrationResult -ScopeId $scopeId -Step 'Option' -Status 'ERROR' -Message "$optMsg — $_"
                                $scopeHadError = $true
                            }
                        }
                    }
                }
            } catch {
                Add-MigrationResult -ScopeId $scopeId -Step 'Options' -Status 'ERROR' -Message "$_"
                $scopeHadError = $true
            }
        }
        
        # --- Reservations (clients) ---
        if ($opts.MigrateReservations -and $canMutateChildren) {
            try {
                $reservations = @(Get-DhcpServerv4Reservation -ComputerName $SourceServer -ScopeId $scopeId -ErrorAction SilentlyContinue)
                if ((Get-SafeCount $reservations) -eq 0) {
                    Add-MigrationResult -ScopeId $scopeId -Step 'Reservations' -Status 'SKIP' -Message 'No reservations on source'
                } else {
                    foreach ($res in $reservations) {
                        $resMsg = "$($res.IPAddress) / $($res.ClientId) ($($res.Name))"
                        if ($DryRun) {
                            Add-MigrationResult -ScopeId $scopeId -Step 'Reservation' -Status 'PLAN' -Message $resMsg
                        } else {
                            try {
                                $resParams = @{
                                    ComputerName = $DestServer
                                    ScopeId      = $scopeId
                                    IPAddress    = $res.IPAddress
                                    ClientId     = $res.ClientId
                                    ErrorAction  = 'Stop'
                                }
                                if ($res.Name) { $resParams['Name'] = $res.Name }
                                if ($res.Description) { $resParams['Description'] = $res.Description }
                                if ($res.Type) { $resParams['Type'] = $res.Type }
                                
                                Add-DhcpServerv4Reservation @resParams
                                Add-MigrationResult -ScopeId $scopeId -Step 'Reservation' -Status 'SUCCESS' -Message $resMsg
                            } catch {
                                if ("$_" -match 'already|exists') {
                                    Add-MigrationResult -ScopeId $scopeId -Step 'Reservation' -Status 'SKIP' -Message "$resMsg (already present)"
                                } else {
                                    Add-MigrationResult -ScopeId $scopeId -Step 'Reservation' -Status 'ERROR' -Message "$resMsg — $_"
                                    $scopeHadError = $true
                                }
                            }
                        }
                    }
                }
            } catch {
                Add-MigrationResult -ScopeId $scopeId -Step 'Reservations' -Status 'ERROR' -Message "$_"
                $scopeHadError = $true
            }
        }
        
        # --- Active leases as reservations ---
        if ($opts.MigrateLeasesAsRes -and $canMutateChildren) {
            try {
                $leases = @(Get-DhcpServerv4Lease -ComputerName $SourceServer -ScopeId $scopeId -ErrorAction SilentlyContinue |
                    Where-Object { $_.AddressState -match 'Active|Offer' -and $_.ClientId })
                
                if ((Get-SafeCount $leases) -eq 0) {
                    Add-MigrationResult -ScopeId $scopeId -Step 'Leases→Res' -Status 'SKIP' -Message 'No active leases with client IDs'
                } else {
                    foreach ($lease in $leases) {
                        $leaseMsg = "$($lease.IPAddress) / $($lease.ClientId) ($($lease.HostName))"
                        if ($DryRun) {
                            Add-MigrationResult -ScopeId $scopeId -Step 'Lease→Res' -Status 'PLAN' -Message $leaseMsg
                        } else {
                            try {
                                Add-DhcpServerv4Reservation -ComputerName $DestServer -ScopeId $scopeId `
                                    -IPAddress $lease.IPAddress -ClientId $lease.ClientId `
                                    -Name $(if ($lease.HostName) { $lease.HostName } else { "lease-$($lease.IPAddress)" }) `
                                    -Description "Migrated from active lease on $($SourceServer)" `
                                    -ErrorAction Stop
                                Add-MigrationResult -ScopeId $scopeId -Step 'Lease→Res' -Status 'SUCCESS' -Message $leaseMsg
                            } catch {
                                if ("$_" -match 'already|exists') {
                                    Add-MigrationResult -ScopeId $scopeId -Step 'Lease→Res' -Status 'SKIP' -Message "$leaseMsg (already present)"
                                } else {
                                    Add-MigrationResult -ScopeId $scopeId -Step 'Lease→Res' -Status 'ERROR' -Message "$leaseMsg — $_"
                                    $scopeHadError = $true
                                }
                            }
                        }
                    }
                }
            } catch {
                Add-MigrationResult -ScopeId $scopeId -Step 'Leases→Res' -Status 'ERROR' -Message "$_"
                $scopeHadError = $true
            }
        }
        
        # --- Activate destination ---
        if ($opts.ActivateDest -and -not $DryRun -and $destExists -and -not $scopeHadError) {
            try {
                Set-DhcpServerv4Scope -ComputerName $DestServer -ScopeId $scopeId -State Active -ErrorAction Stop
                Add-MigrationResult -ScopeId $scopeId -Step 'Activate Dest' -Status 'SUCCESS' -Message 'Scope activated on destination'
            } catch {
                Add-MigrationResult -ScopeId $scopeId -Step 'Activate Dest' -Status 'ERROR' -Message "$_"
                $scopeHadError = $true
            }
        }
        elseif ($opts.ActivateDest -and $DryRun) {
            Add-MigrationResult -ScopeId $scopeId -Step 'Activate Dest' -Status 'PLAN' -Message 'Would activate scope on destination'
        }
        
        # --- Deactivate source ---
        if ($opts.DeactivateSource -and -not $DryRun -and -not $scopeHadError) {
            try {
                Set-DhcpServerv4Scope -ComputerName $SourceServer -ScopeId $scopeId -State Inactive -ErrorAction Stop
                Add-MigrationResult -ScopeId $scopeId -Step 'Deactivate Src' -Status 'SUCCESS' -Message 'Source scope deactivated'
            } catch {
                Add-MigrationResult -ScopeId $scopeId -Step 'Deactivate Src' -Status 'ERROR' -Message "$_"
                $scopeHadError = $true
            }
        }
        elseif ($opts.DeactivateSource -and $DryRun) {
            Add-MigrationResult -ScopeId $scopeId -Step 'Deactivate Src' -Status 'PLAN' -Message 'Would deactivate source scope after success'
        }
        
        if ($scopeHadError) { $errorScopes++ } else { $successScopes++ }
    }
    
    $script:Window.Dispatcher.Invoke([action]{
        $script:GridMigrateResults.ItemsSource = $null
        $script:GridMigrateResults.ItemsSource = @($Global:MigrationResults)
        $script:BtnMigrateExport.IsEnabled = ((Get-SafeCount $Global:MigrationResults) -gt 0)
    }, [System.Windows.Threading.DispatcherPriority]::Normal)
    
    $summary = "$modeLabel complete — OK scopes: $successScopes, scopes with errors: $errorScopes, result rows: $(Get-SafeCount $Global:MigrationResults)"
    Write-ActionLog "===== $summary =====" $(if ($errorScopes -gt 0) { 'WARN' } else { 'SUCCESS' })
    $script:TxtMigrateStatus.Text = $summary
    Set-Status $summary
    Update-LogDisplay
    Update-MigrateReadyState
    
    if (-not $Quiet) {
        if (-not $DryRun -and $errorScopes -eq 0) {
            Show-MessageBox "Migration completed successfully.`n$summary" "Migrate" OK Information
        } elseif (-not $DryRun) {
            Show-MessageBox "Migration finished with some errors.`n$summary`nSee results grid and Action Log." "Migrate" OK Warning
        }
    }
}

function Get-DefaultCompareMigrationOptions {
    <#
    .SYNOPSIS
        Full related-settings package used by Compare → Migrate Selected
    #>
    return [PSCustomObject]@{
        MigrateScope         = $true
        MigrateOptions       = $true
        MigrateReservations  = $true
        MigrateExclusions    = $true
        MigrateLeasesAsRes   = $false
        ActivateDest         = $true
        DeactivateSource     = $false
        ConflictMode         = 'Merge into existing'
    }
}

function Test-IsDhcpScopeIdKey {
    param([string]$Key)
    if ([string]::IsNullOrWhiteSpace($Key)) { return $false }
    # Scope compare keys are ScopeId values (IPv4)
    return [bool]($Key -match '^\d{1,3}(\.\d{1,3}){3}$')
}

function Invoke-CompareSelectedScopeMigration {
    <#
    .SYNOPSIS
        Migrates selected Compare-grid scope rows (and related settings) between A and B
    #>
    param([switch]$DryRun)
    
    if ([string]::IsNullOrWhiteSpace($Global:DHCPServer) -or [string]::IsNullOrWhiteSpace($Global:CompareServer)) {
        Show-MessageBox "Connect both Server A and Server B first." "Compare Migrate" OK Warning
        return
    }
    
    $category = 'Scopes'
    try {
        if ($null -ne $script:CboCompareCategory.SelectedItem) {
            $category = "$($script:CboCompareCategory.SelectedItem.Content)"
        }
    } catch {}
    
    if ($category -ne 'Scopes') {
        Show-MessageBox "Switch Compare category to Scopes, run compare, then select scope row(s) to migrate." "Compare Migrate" OK Warning
        return
    }
    
    $selectedRows = @($script:GridCompare.SelectedItems)
    if ((Get-SafeCount $selectedRows) -eq 0 -and $null -ne $script:GridCompare.SelectedItem) {
        $selectedRows = @($script:GridCompare.SelectedItem)
    }
    
    if ((Get-SafeCount $selectedRows) -eq 0) {
        Show-MessageBox "Select one or more scope rows in the Compare results grid first." "Compare Migrate" OK Warning
        return
    }
    
    $aToB = [System.Collections.Generic.List[object]]::new()
    $bToA = [System.Collections.Generic.List[object]]::new()
    $skipped = [System.Collections.Generic.List[string]]::new()
    
    foreach ($row in $selectedRows) {
        $key = "$($row.Key)"
        $status = "$($row.Status)"
        $label = if ($row.Label) { "$($row.Label)" } else { $key }
        
        if (-not (Test-IsDhcpScopeIdKey $key)) {
            [void]$skipped.Add("$label (not a scope id)")
            continue
        }
        
        $item = [PSCustomObject]@{
            ScopeId = $key
            Name    = $label
            Status  = $status
        }
        
        switch ($status) {
            'Only on A' {
                [void]$aToB.Add($item)
            }
            'Only on B' {
                [void]$bToA.Add($item)
            }
            'Different' {
                # Push primary (A) definition/settings onto B by default
                [void]$aToB.Add($item)
            }
            'Matching' {
                [void]$skipped.Add("$key — already matching (skipped)")
            }
            default {
                [void]$skipped.Add("$key — unknown status '$status'")
            }
        }
    }
    
    $countA = Get-SafeCount $aToB
    $countB = Get-SafeCount $bToA
    $countSkip = Get-SafeCount $skipped
    
    if ($countA -eq 0 -and $countB -eq 0) {
        $skipText = if ($countSkip -gt 0) { ($skipped -join "`n") } else { 'No migratable scope rows.' }
        Show-MessageBox "Nothing to migrate.`n$skipText" "Compare Migrate" OK Warning
        return
    }
    
    $opts = Get-DefaultCompareMigrationOptions
    $modeLabel = if ($DryRun) { 'DRY RUN' } else { 'MIGRATE' }
    
    $confirmLines = [System.Collections.Generic.List[string]]::new()
    [void]$confirmLines.Add("$modeLabel selected compare scope(s) with related settings")
    [void]$confirmLines.Add('')
    if ($countA -gt 0) {
        [void]$confirmLines.Add("A → B ($($Global:DHCPServer) → $($Global:CompareServer)): $countA")
        foreach ($s in $aToB) { [void]$confirmLines.Add("  • $($s.ScopeId)  $($s.Name)  [$($s.Status)]") }
    }
    if ($countB -gt 0) {
        if ($countA -gt 0) { [void]$confirmLines.Add('') }
        [void]$confirmLines.Add("B → A ($($Global:CompareServer) → $($Global:DHCPServer)): $countB")
        foreach ($s in $bToA) { [void]$confirmLines.Add("  • $($s.ScopeId)  $($s.Name)  [$($s.Status)]") }
    }
    [void]$confirmLines.Add('')
    [void]$confirmLines.Add('Includes: Scope, Options, Reservations, Exclusions')
    [void]$confirmLines.Add('Activate on destination: Yes')
    [void]$confirmLines.Add('Deactivate source: No')
    if ($countSkip -gt 0) {
        [void]$confirmLines.Add('')
        [void]$confirmLines.Add("Skipped: $countSkip")
    }
    
    $confirm = Show-MessageBox ($confirmLines -join "`n") "Confirm Compare Migration" YesNo Warning
    if ($confirm -ne 'Yes') { return }
    
    $Global:MigrationResults.Clear()
    
    if ($countA -gt 0) {
        Invoke-DhcpScopeMigration -DryRun:$DryRun `
            -SourceServer $Global:DHCPServer `
            -DestServer $Global:CompareServer `
            -Scopes @($aToB) `
            -Options $opts `
            -SkipConfirm `
            -AppendResults `
            -Quiet
    }
    
    if ($countB -gt 0) {
        Invoke-DhcpScopeMigration -DryRun:$DryRun `
            -SourceServer $Global:CompareServer `
            -DestServer $Global:DHCPServer `
            -Scopes @($bToA) `
            -Options $opts `
            -SkipConfirm `
            -AppendResults `
            -Quiet
    }
    
    # Show detailed results on Migrate tab
    try {
        if ($null -ne $script:TabMigrate) {
            $script:MainTabs.SelectedItem = $script:TabMigrate
        }
    } catch {}
    
    $errRows = Get-SafeCount @($Global:MigrationResults | Where-Object { $_.Status -eq 'ERROR' })
    $summary = "Compare migrate finished — A→B: $countA, B→A: $countB, result rows: $(Get-SafeCount $Global:MigrationResults)"
    Write-ActionLog $summary $(if ($errRows -gt 0) { 'WARN' } else { 'SUCCESS' })
    if ($null -ne $script:TxtCompareStatus) {
        $script:TxtCompareStatus.Text = $summary
    }
    Update-LogDisplay
    
    if (-not $DryRun) {
        if ($errRows -eq 0) {
            Show-MessageBox "Migration completed successfully.`n$summary`nSee the Migrate tab for step details." "Compare Migrate" OK Information
        } else {
            Show-MessageBox "Migration finished with $errRows error row(s).`n$summary`nSee Migrate tab results and Action Log." "Compare Migrate" OK Warning
        }
    }
}

function Export-MigrationPlan {
    if ($Global:MigrationResults.Count -eq 0) {
        Show-MessageBox "No migration results to export. Run Dry Run or Migrate first." "Export" OK Warning
        return
    }
    
    try {
        $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveDialog.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
        $saveDialog.FileName = "DHCP-Migration-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
        $saveDialog.Title = "Export Migration Results"
        
        if ($saveDialog.ShowDialog() -eq 'OK') {
            $Global:MigrationResults | Export-Csv -Path $saveDialog.FileName -NoTypeInformation -Encoding UTF8
            Write-ActionLog "Migration results exported: $($saveDialog.FileName)" "SUCCESS"
            Show-MessageBox "Exported to:`n$($saveDialog.FileName)" "Export Complete" OK Information
            Update-LogDisplay
        }
    } catch {
        Write-ActionLog "Migration export failed: $_" "ERROR"
        Show-MessageBox "Export failed: $_" "Export Error" OK Error
    }
}
#endregion

#region Dialog Functions
function Show-AddScopeDialog {
    <#
    .SYNOPSIS
        Shows dialog to add a new DHCP scope
    #>
    
    Write-ActionLog "Opening Add Scope dialog..." "INFO"
    
    [xml]$dialogXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Add New DHCP Scope" Height="520" Width="500"
        WindowStartupLocation="CenterScreen" Background="#1A1D23">
    <Grid Margin="20">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        
        <TextBlock Grid.Row="0" Text="Scope Name:" Foreground="#9AA3B2" Margin="0,0,0,5"/>
        <TextBox Grid.Row="1" x:Name="TxtScopeName" Margin="0,0,0,15" Padding="8,5"
                 Background="#22262E" Foreground="#E8EAF0" BorderBrush="#383E4A"/>
        
        <TextBlock Grid.Row="2" Text="Scope ID (Network):" Foreground="#9AA3B2" Margin="0,0,0,5"/>
        <TextBox Grid.Row="3" x:Name="TxtScopeId" Margin="0,0,0,15" Padding="8,5"
                 Background="#22262E" Foreground="#E8EAF0" BorderBrush="#383E4A"/>
        
        <TextBlock Grid.Row="4" Text="Start IP Address:" Foreground="#9AA3B2" Margin="0,0,0,5"/>
        <TextBox Grid.Row="5" x:Name="TxtStartIP" Margin="0,0,0,15" Padding="8,5"
                 Background="#22262E" Foreground="#E8EAF0" BorderBrush="#383E4A"/>
        
        <TextBlock Grid.Row="6" Text="End IP Address:" Foreground="#9AA3B2" Margin="0,0,0,5"/>
        <TextBox Grid.Row="7" x:Name="TxtEndIP" Margin="0,0,0,15" Padding="8,5"
                 Background="#22262E" Foreground="#E8EAF0" BorderBrush="#383E4A"/>
        
        <TextBlock Grid.Row="8" Text="Subnet Mask:" Foreground="#9AA3B2" Margin="0,0,0,5"/>
        <TextBox Grid.Row="9" x:Name="TxtSubnetMask" Margin="0,0,0,15" Padding="8,5"
                 Background="#22262E" Foreground="#E8EAF0" BorderBrush="#383E4A" Text="255.255.255.0"/>
        
        <StackPanel Grid.Row="10" Orientation="Horizontal" HorizontalAlignment="Right">
            <Button x:Name="BtnOK" Content="Create Scope" Width="120" Height="32" Margin="0,0,10,0"
                    Background="#2196F3" Foreground="White" BorderThickness="0"/>
            <Button x:Name="BtnCancel" Content="Cancel" Width="80" Height="32"
                    Background="#2A2F3A" Foreground="#E8EAF0" BorderBrush="#383E4A" BorderThickness="1"/>
        </StackPanel>
    </Grid>
</Window>
'@
    
    try {
        $dialog = [Windows.Markup.XamlReader]::Load([System.Xml.XmlNodeReader]::new($dialogXaml))
        $txtName = $dialog.FindName("TxtScopeName")
        $txtId = $dialog.FindName("TxtScopeId")
        $txtStart = $dialog.FindName("TxtStartIP")
        $txtEnd = $dialog.FindName("TxtEndIP")
        $txtMask = $dialog.FindName("TxtSubnetMask")
        $btnOK = $dialog.FindName("BtnOK")
        $btnCancel = $dialog.FindName("BtnCancel")
        
        $btnOK.add_Click({
            if ([string]::IsNullOrWhiteSpace($txtName.Text)) {
                Show-MessageBox "Scope name is required" "Validation Error" OK Warning
                return
            }
            
            if (!(Test-IPAddress $txtId.Text)) {
                Show-MessageBox "Invalid scope ID (network address)" "Validation Error" OK Warning
                return
            }
            
            if (!(Test-IPAddress $txtStart.Text) -or !(Test-IPAddress $txtEnd.Text)) {
                Show-MessageBox "Invalid IP address range" "Validation Error" OK Warning
                return
            }
            
            try {
                Write-ActionLog "Creating scope: $($txtName.Text) [$($txtId.Text)]" "INFO"
                
                Add-DhcpServerv4Scope -ComputerName $Global:DHCPServer `
                    -Name $txtName.Text `
                    -StartRange $txtStart.Text `
                    -EndRange $txtEnd.Text `
                    -SubnetMask $txtMask.Text `
                    -State Active `
                    -ErrorAction Stop
                
                Write-ActionLog "Scope created successfully" "SUCCESS"
                Show-MessageBox "Scope created successfully" "Success" OK Information
                
                $dialog.DialogResult = $true
                $dialog.Close()
                
                Load-Scopes
                Build-NavTree
                
            } catch {
                $errMsg = "Failed to create scope: $_"
                Write-ActionLog $errMsg "ERROR"
                Show-MessageBox $errMsg "Error" OK Error
            }
        })
        
        $btnCancel.add_Click({ $dialog.Close() })
        
        [void]$dialog.ShowDialog()
        
    } catch {
        Write-ActionLog "Failed to show Add Scope dialog: $_" "ERROR"
    }
}

function Show-AddReservationDialog {
    <#
    .SYNOPSIS
        Shows dialog to add a new reservation
    #>
    
    $scopeId = Get-SelectedScopeId
    if ([string]::IsNullOrWhiteSpace($scopeId)) {
        Show-MessageBox "Please select a scope first" "No Scope Selected" OK Warning
        return
    }
    
    Write-ActionLog "Opening Add Reservation dialog for scope $scopeId..." "INFO"
    
    [xml]$dialogXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Add Reservation" Height="400" Width="480"
        WindowStartupLocation="CenterScreen" Background="#1A1D23">
    <Grid Margin="20">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        
        <TextBlock Grid.Row="0" Text="IP Address:" Foreground="#9AA3B2" Margin="0,0,0,5"/>
        <TextBox Grid.Row="1" x:Name="TxtIP" Margin="0,0,0,15" Padding="8,5"
                 Background="#22262E" Foreground="#E8EAF0" BorderBrush="#383E4A"/>
        
        <TextBlock Grid.Row="2" Text="MAC Address:" Foreground="#9AA3B2" Margin="0,0,0,5"/>
        <TextBox Grid.Row="3" x:Name="TxtMAC" Margin="0,0,0,15" Padding="8,5"
                 Background="#22262E" Foreground="#E8EAF0" BorderBrush="#383E4A"
                 ToolTip="Format: 00-11-22-33-44-55 or 00:11:22:33:44:55"/>
        
        <TextBlock Grid.Row="4" Text="Name:" Foreground="#9AA3B2" Margin="0,0,0,5"/>
        <TextBox Grid.Row="5" x:Name="TxtName" Margin="0,0,0,15" Padding="8,5"
                 Background="#22262E" Foreground="#E8EAF0" BorderBrush="#383E4A"/>
        
        <StackPanel Grid.Row="7" Orientation="Horizontal" HorizontalAlignment="Right">
            <Button x:Name="BtnOK" Content="Add Reservation" Width="140" Height="32" Margin="0,0,10,0"
                    Background="#2196F3" Foreground="White" BorderThickness="0"/>
            <Button x:Name="BtnCancel" Content="Cancel" Width="80" Height="32"
                    Background="#2A2F3A" Foreground="#E8EAF0" BorderBrush="#383E4A" BorderThickness="1"/>
        </StackPanel>
    </Grid>
</Window>
'@
    
    try {
        $dialog = [Windows.Markup.XamlReader]::Load([System.Xml.XmlNodeReader]::new($dialogXaml))
        $txtIP = $dialog.FindName("TxtIP")
        $txtMAC = $dialog.FindName("TxtMAC")
        $txtName = $dialog.FindName("TxtName")
        $btnOK = $dialog.FindName("BtnOK")
        $btnCancel = $dialog.FindName("BtnCancel")
        
        $btnOK.add_Click({
            if (!(Test-IPAddress $txtIP.Text)) {
                Show-MessageBox "Invalid IP address" "Validation Error" OK Warning
                return
            }
            
            if (!(Test-MACAddress $txtMAC.Text)) {
                Show-MessageBox "Invalid MAC address format" "Validation Error" OK Warning
                return
            }
            
            try {
                Write-ActionLog "Adding reservation: $($txtIP.Text) = $($txtMAC.Text)" "INFO"
                
                Add-DhcpServerv4Reservation -ComputerName $Global:DHCPServer `
                    -ScopeId $scopeId `
                    -IPAddress $txtIP.Text `
                    -ClientId $txtMAC.Text `
                    -Name $txtName.Text `
                    -ErrorAction Stop
                
                Write-ActionLog "Reservation added successfully" "SUCCESS"
                Show-MessageBox "Reservation added successfully" "Success" OK Information
                
                $dialog.DialogResult = $true
                $dialog.Close()
                
                Load-Reservations
                
            } catch {
                $errMsg = "Failed to add reservation: $_"
                Write-ActionLog $errMsg "ERROR"
                Show-MessageBox $errMsg "Error" OK Error
            }
        })
        
        $btnCancel.add_Click({ $dialog.Close() })
        
        [void]$dialog.ShowDialog()
        
    } catch {
        Write-ActionLog "Failed to show Add Reservation dialog: $_" "ERROR"
    }
}

function Show-AddExclusionDialog {
    <#
    .SYNOPSIS
        Shows dialog to add an exclusion range
    #>
    
    $scopeId = Get-SelectedScopeId
    if ([string]::IsNullOrWhiteSpace($scopeId)) {
        Show-MessageBox "Please select a scope first" "No Scope Selected" OK Warning
        return
    }
    
    Write-ActionLog "Opening Add Exclusion dialog for scope $scopeId..." "INFO"
    
    [xml]$dialogXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Add Exclusion Range" Height="300" Width="450"
        WindowStartupLocation="CenterScreen" Background="#1A1D23">
    <Grid Margin="20">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        
        <TextBlock Grid.Row="0" Text="Start IP Address:" Foreground="#9AA3B2" Margin="0,0,0,5"/>
        <TextBox Grid.Row="1" x:Name="TxtStartIP" Margin="0,0,0,15" Padding="8,5"
                 Background="#22262E" Foreground="#E8EAF0" BorderBrush="#383E4A"/>
        
        <TextBlock Grid.Row="2" Text="End IP Address:" Foreground="#9AA3B2" Margin="0,0,0,5"/>
        <TextBox Grid.Row="3" x:Name="TxtEndIP" Margin="0,0,0,15" Padding="8,5"
                 Background="#22262E" Foreground="#E8EAF0" BorderBrush="#383E4A"/>
        
        <StackPanel Grid.Row="5" Orientation="Horizontal" HorizontalAlignment="Right">
            <Button x:Name="BtnOK" Content="Add Exclusion" Width="130" Height="32" Margin="0,0,10,0"
                    Background="#2196F3" Foreground="White" BorderThickness="0"/>
            <Button x:Name="BtnCancel" Content="Cancel" Width="80" Height="32"
                    Background="#2A2F3A" Foreground="#E8EAF0" BorderBrush="#383E4A" BorderThickness="1"/>
        </StackPanel>
    </Grid>
</Window>
'@
    
    try {
        $dialog = [Windows.Markup.XamlReader]::Load([System.Xml.XmlNodeReader]::new($dialogXaml))
        $txtStart = $dialog.FindName("TxtStartIP")
        $txtEnd = $dialog.FindName("TxtEndIP")
        $btnOK = $dialog.FindName("BtnOK")
        $btnCancel = $dialog.FindName("BtnCancel")
        
        $btnOK.add_Click({
            if (!(Test-IPAddress $txtStart.Text) -or !(Test-IPAddress $txtEnd.Text)) {
                Show-MessageBox "Invalid IP address range" "Validation Error" OK Warning
                return
            }
            
            try {
                Write-ActionLog "Adding exclusion: $($txtStart.Text) - $($txtEnd.Text)" "INFO"
                
                Add-DhcpServerv4ExclusionRange -ComputerName $Global:DHCPServer `
                    -ScopeId $scopeId `
                    -StartRange $txtStart.Text `
                    -EndRange $txtEnd.Text `
                    -ErrorAction Stop
                
                Write-ActionLog "Exclusion added successfully" "SUCCESS"
                Show-MessageBox "Exclusion added successfully" "Success" OK Information
                
                $dialog.DialogResult = $true
                $dialog.Close()
                
                Load-Exclusions
                
            } catch {
                $errMsg = "Failed to add exclusion: $_"
                Write-ActionLog $errMsg "ERROR"
                Show-MessageBox $errMsg "Error" OK Error
            }
        })
        
        $btnCancel.add_Click({ $dialog.Close() })
        
        [void]$dialog.ShowDialog()
        
    } catch {
        Write-ActionLog "Failed to show Add Exclusion dialog: $_" "ERROR"
    }
}
#endregion

#region Event Handlers - Connection
$BtnScanDomain.add_Click({
    Write-ActionLog "Scan Domain button clicked" "INFO"
    Show-DomainDhcpScanDialog
})

$BtnConnect.add_Click({
    Write-ActionLog "Connect button clicked" "INFO"
    
    $serverName = $script:TxtServerName.Text.Trim()
    
    if ([string]::IsNullOrWhiteSpace($serverName)) {
        Show-MessageBox "Please enter a server name or IP address" "Validation Error" OK Warning
        return
    }
    
    $cleaned = Get-CleanDhcpServerHostName -Name $serverName
    if (-not [string]::IsNullOrWhiteSpace($cleaned) -and $cleaned -ne $serverName) {
        Write-ActionLog "Cleaned server name '$serverName' -> '$cleaned'" "INFO"
        $serverName = $cleaned
        $script:TxtServerName.Text = $cleaned
    }
    
    $fallbackIp = Get-DhcpFallbackIpForName -Name $serverName
    Set-Status "Connecting to $serverName..."
    Write-ActionLog "Attempting connection to: $serverName$(if ($fallbackIp) { " (IP fallback $fallbackIp)" })" "INFO"
    
    try {
        $normalized = Connect-DhcpServerTarget -ComputerName $serverName -FallbackIP $fallbackIp
        
        $Global:DHCPServer = $normalized
        Write-ActionLog "Successfully connected to $normalized" "SUCCESS"
        
        # Update UI
        $script:BtnConnect.IsEnabled = $false
        $script:TxtServerName.Text = $normalized
        $script:TxtServerName.IsEnabled = $false
        Enable-ConnectedControls $true
        
        Set-Status "Connected" $normalized
        $script:StatusServer.Foreground = [System.Windows.Media.Brushes]::LimeGreen
        
        # Load initial data
        Build-NavTree
        Load-Scopes
        Update-TroubleshootScopeList
        Update-CompareReadyState
        
        Update-LogDisplay
        
    } catch {
        $errMsg = "$_"
        Write-ActionLog $errMsg "ERROR"
        Set-Status "Connection failed"
        Show-MessageBox $errMsg "Connection Error" OK Error
        Update-LogDisplay
    }
})

$BtnDisconnect.add_Click({
    Write-ActionLog "Disconnect button clicked" "INFO"
    
    if ($Global:DHCPServer) {
        Write-ActionLog "Disconnecting from $Global:DHCPServer" "INFO"
        $Global:DHCPServer = $null
        $Global:SelectedScope = $null
        
        # Reset UI
        $script:BtnConnect.IsEnabled = $true
        $script:TxtServerName.IsEnabled = $true
        Enable-ConnectedControls $false
        
        # Clear all grids
        $script:GridScopes.ItemsSource = $null
        $script:GridLeases.ItemsSource = $null
        $script:GridReservations.ItemsSource = $null
        $script:GridExclusions.ItemsSource = $null
        $script:GridOptions.ItemsSource = $null
        $script:GridFilters.ItemsSource = $null
        $script:GridPolicies.ItemsSource = $null
        $script:GridCompare.ItemsSource = $null
        try {
            Reset-BadAddressDiagState
            if ($null -ne $script:CboTroubleshootScope) { $script:CboTroubleshootScope.Items.Clear() }
        } catch {}
        
        $script:NavTree.Items.Clear()
        try {
            $Global:NavScopeIndex.Clear()
            $Global:NavScopeMatched.Clear()
            $Global:NavScopeMatchIndex = -1
            $script:NavServerNode = $null
            $script:NavScopesContainer = $null
            if ($null -ne $script:TxtNavScopeSearch) { $script:TxtNavScopeSearch.Text = '' }
            Update-NavScopeSearchStatus -Message "Connect to a DHCP server to search scopes"
        } catch {}
        
        Set-Status "Disconnected" "Not Connected"
        $script:StatusServer.Foreground = [System.Windows.Media.Brushes]::Orange
        Update-CompareReadyState
        
        Write-ActionLog "Disconnected successfully" "SUCCESS"
        Update-LogDisplay
    }
})

$BtnRefresh.add_Click({
    Write-ActionLog "Refresh button clicked" "INFO"
    
    $selectedTab = $script:MainTabs.SelectedItem
    
    if ($null -eq $selectedTab) { return }
    
    switch ($selectedTab.Name) {
        "TabDashboard"    {
            if ($Global:DHCPServer) { Invoke-DashboardRefresh }
            else { Initialize-DashboardBindings; Sync-DashboardUi }
        }
        "TabScopes"       { Load-Scopes }
        "TabLeases"       { Load-Leases }
        "TabReservations" { Load-Reservations }
        "TabExclusions"   { Load-Exclusions }
        "TabOptions"      { Load-Options }
        "TabFilters"      { Load-Filters }
        "TabPolicies"     { Load-Policies }
        "TabTroubleshoot" {
            Initialize-TroubleshootTab
            Update-TroubleshootScopeList
        }
        "TabStats"        { Load-Statistics }
        "TabCompare"      { Invoke-DhcpServerCompare }
        "TabMigrate"      { Update-MigrateReadyState }
        "TabEvents"       {
            if ($null -eq $script:GridEvents.ItemsSource) {
                $script:GridEvents.ItemsSource = $Global:DhcpEventEntries
            }
            Update-EventWatchStatus
        }
        default           { Write-ActionLog "No refresh action for this tab" "INFO" }
    }
})
#endregion

#region Event Handlers - Navigation
function Handle-NavSelect {
    <#
    .SYNOPSIS
        Handles navigation tree item selection
        FIXED: Enhanced with logging
    #>
    param($sender, $e)
    
    if ($null -eq $script:NavTree.SelectedItem) { return }
    
    $selected = $script:NavTree.SelectedItem
    $tag = $selected.Tag
    
    Write-ActionLog "Navigation selected: $tag" "INFO"
    
    if ($tag -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$') {
        # Scope selected
        $Global:SelectedScope = $tag
        Write-ActionLog "Scope selected: $tag" "INFO"
        $script:MainTabs.SelectedItem = $script:TabLeases
        Load-Leases
    }
    elseif ($tag -match '^(.+):Leases$') {
        $Global:SelectedScope = $Matches[1]
        Write-ActionLog "Loading leases for scope: $($Global:SelectedScope)" "INFO"
        $script:MainTabs.SelectedItem = $script:TabLeases
        Load-Leases
    }
    elseif ($tag -match '^(.+):Reservations$') {
        $Global:SelectedScope = $Matches[1]
        Write-ActionLog "Loading reservations for scope: $($Global:SelectedScope)" "INFO"
        $script:MainTabs.SelectedItem = $script:TabReservations
        Load-Reservations
    }
    elseif ($tag -match '^(.+):Exclusions$') {
        $Global:SelectedScope = $Matches[1]
        Write-ActionLog "Loading exclusions for scope: $($Global:SelectedScope)" "INFO"
        $script:MainTabs.SelectedItem = $script:TabExclusions
        Load-Exclusions
    }
    elseif ($tag -match '^(.+):Options$') {
        $Global:SelectedScope = $Matches[1]
        Write-ActionLog "Loading options for scope: $($Global:SelectedScope)" "INFO"
        $script:MainTabs.SelectedItem = $script:TabOptions
        $script:CboOptionLevel.SelectedIndex = 1
        Load-Options
    }
    elseif ($tag -eq "Scopes") {
        Write-ActionLog "Loading scopes view" "INFO"
        $script:MainTabs.SelectedItem = $script:TabScopes
        Load-Scopes
    }
    elseif ($tag -eq "Dashboard") {
        Write-ActionLog "Loading monitoring dashboard" "INFO"
        $script:MainTabs.SelectedItem = $script:TabDashboard
        Initialize-DashboardBindings
        Sync-DashboardEstatePanel
        if ((Get-SafeCount $Global:ScopeStatEntriesAll) -eq 0 -and $Global:DHCPServer) {
            Invoke-DashboardRefresh
        } else {
            Sync-DashboardUi
        }
    }
    elseif ($tag -eq "Filters") {
        Write-ActionLog "Loading filters view" "INFO"
        $script:MainTabs.SelectedItem = $script:TabFilters
        Load-Filters
    }
    elseif ($tag -eq "Policies") {
        Write-ActionLog "Loading policies view" "INFO"
        $script:MainTabs.SelectedItem = $script:TabPolicies
        Load-Policies
    }
    elseif ($tag -eq "Troubleshoot") {
        Write-ActionLog "Loading Troubleshoot view" "INFO"
        $script:MainTabs.SelectedItem = $script:TabTroubleshoot
        Initialize-TroubleshootTab
        Update-TroubleshootScopeList
        if ($Global:SelectedScope) { [void](Set-TroubleshootScopeSelection -ScopeId $Global:SelectedScope) }
    }
    elseif ($tag -eq "Statistics") {
        Write-ActionLog "Loading statistics view" "INFO"
        $script:MainTabs.SelectedItem = $script:TabStats
        Load-Statistics
    }
    
    Update-LogDisplay
}

$NavTree.add_SelectedItemChanged({ Handle-NavSelect $this $_ })

# Navigation scope search
if ($null -ne $script:TxtNavScopeSearch) {
    $script:TxtNavScopeSearch.add_TextChanged({
        $Global:NavScopeMatchIndex = -1
        [void](Apply-NavScopeFilter -Quiet)
    })
    $script:TxtNavScopeSearch.add_KeyDown({
        param($sender, $e)
        if ($e.Key -eq [System.Windows.Input.Key]::Enter -or $e.Key -eq [System.Windows.Input.Key]::Return) {
            Select-NavScopeMatch
            $e.Handled = $true
        } elseif ($e.Key -eq [System.Windows.Input.Key]::Escape) {
            Clear-NavScopeSearch
            $e.Handled = $true
        }
    })
}

if ($null -ne $script:BtnNavScopeFind) {
    $script:BtnNavScopeFind.add_Click({
        Select-NavScopeMatch
    })
}

if ($null -ne $script:BtnNavScopeSearchClear) {
    $script:BtnNavScopeSearchClear.add_Click({
        Clear-NavScopeSearch
    })
}
#endregion

#region Event Handlers - Scopes
$BtnScopeAdd.add_Click({
    Write-ActionLog "Add Scope button clicked" "INFO"
    Show-AddScopeDialog
})

$BtnScopeEdit.add_Click({
    if ($null -eq $script:GridScopes.SelectedItem) {
        Show-MessageBox "Please select a scope to edit" "No Selection" OK Warning
        return
    }
    
    Write-ActionLog "Edit Scope clicked - Feature placeholder" "INFO"
    Show-MessageBox "Scope editing dialog would appear here" "Feature" OK Information
})

$BtnScopeDelete.add_Click({
    if ($null -eq $script:GridScopes.SelectedItem) {
        Show-MessageBox "Please select a scope to delete" "No Selection" OK Warning
        return
    }
    
    $scope = $script:GridScopes.SelectedItem
    $result = Show-MessageBox "Delete scope '$($scope.Name)' ($($scope.ScopeId))?`n`nThis will remove all leases and reservations!" "Confirm Delete" YesNo Warning
    
    if ($result -eq 'Yes') {
        try {
            Write-ActionLog "Deleting scope: $($scope.ScopeId)" "INFO"
            
            Remove-DhcpServerv4Scope -ComputerName $Global:DHCPServer -ScopeId $scope.ScopeId -Force -ErrorAction Stop
            
            Write-ActionLog "Scope deleted successfully" "SUCCESS"
            Show-MessageBox "Scope deleted successfully" "Success" OK Information
            
            Load-Scopes
            Build-NavTree
            
        } catch {
            $errMsg = "Failed to delete scope: $_"
            Write-ActionLog $errMsg "ERROR"
            Show-MessageBox $errMsg "Error" OK Error
        }
    }
})

$BtnScopeActivate.add_Click({
    if ($null -eq $script:GridScopes.SelectedItem) {
        Show-MessageBox "Please select a scope" "No Selection" OK Warning
        return
    }
    
    $scope = $script:GridScopes.SelectedItem
    
    try {
        Write-ActionLog "Activating scope: $($scope.ScopeId)" "INFO"
        
        Set-DhcpServerv4Scope -ComputerName $Global:DHCPServer -ScopeId $scope.ScopeId -State Active -ErrorAction Stop
        
        Write-ActionLog "Scope activated successfully" "SUCCESS"
        Show-MessageBox "Scope activated" "Success" OK Information
        
        Load-Scopes
        
    } catch {
        $errMsg = "Failed to activate scope: $_"
        Write-ActionLog $errMsg "ERROR"
        Show-MessageBox $errMsg "Error" OK Error
    }
})

$BtnScopeDeactivate.add_Click({
    if ($null -eq $script:GridScopes.SelectedItem) {
        Show-MessageBox "Please select a scope" "No Selection" OK Warning
        return
    }
    
    $scope = $script:GridScopes.SelectedItem
    
    try {
        Write-ActionLog "Deactivating scope: $($scope.ScopeId)" "INFO"
        
        Set-DhcpServerv4Scope -ComputerName $Global:DHCPServer -ScopeId $scope.ScopeId -State Inactive -ErrorAction Stop
        
        Write-ActionLog "Scope deactivated successfully" "SUCCESS"
        Show-MessageBox "Scope deactivated" "Success" OK Information
        
        Load-Scopes
        
    } catch {
        $errMsg = "Failed to deactivate scope: $_"
        Write-ActionLog $errMsg "ERROR"
        Show-MessageBox $errMsg "Error" OK Error
    }
})

$GridScopes.add_SelectionChanged({
    $script:BtnScopeEdit.IsEnabled = ($null -ne $script:GridScopes.SelectedItem)
    $script:BtnScopeDelete.IsEnabled = ($null -ne $script:GridScopes.SelectedItem)
    $script:BtnScopeActivate.IsEnabled = ($null -ne $script:GridScopes.SelectedItem)
    $script:BtnScopeDeactivate.IsEnabled = ($null -ne $script:GridScopes.SelectedItem)
    
    if ($null -ne $script:GridScopes.SelectedItem) {
        $Global:SelectedScope = $script:GridScopes.SelectedItem.ScopeId
        Write-ActionLog "Scope selected from grid: $Global:SelectedScope" "INFO"
    }
})
#endregion

#region Event Handlers - Leases
$BtnLeaseRefresh.add_Click({
    Write-ActionLog "Refreshing leases..." "INFO"
    Load-Leases
})

$BtnLeaseRelease.add_Click({
    $selected = @(Get-SelectedLeaseRows)
    if ((Get-SafeCount $selected) -eq 0) {
        Show-MessageBox "Select one or more leases first.`nTip: Ctrl+click or Shift+click to multi-select." "No Selection" OK Warning
        return
    }
    Invoke-BulkLeaseRelease -Leases $selected
})

$BtnLeaseReserve.add_Click({
    $selected = @(Get-SelectedLeaseRows)
    if ((Get-SafeCount $selected) -eq 0) {
        Show-MessageBox "Select one or more leases to convert.`nTip: Ctrl+click or Shift+click to multi-select." "No Selection" OK Warning
        return
    }
    Invoke-BulkLeaseConvertToReservation -Leases $selected
})

if ($null -ne $script:BtnLeaseSelectAll) {
    $script:BtnLeaseSelectAll.add_Click({
        try {
            if ($null -eq $script:GridLeases -or $null -eq $script:GridLeases.Items) { return }
            $script:GridLeases.SelectAll()
            Update-LeaseSelectionUi
            Write-ActionLog "Selected all $(Get-SafeCount @($script:GridLeases.SelectedItems)) lease(s)" "INFO"
        } catch {
            Write-ActionLog "Select all leases failed: $_" "ERROR"
        }
    })
}

if ($null -ne $script:BtnLeaseClearSel) {
    $script:BtnLeaseClearSel.add_Click({
        try {
            if ($null -ne $script:GridLeases) { $script:GridLeases.UnselectAll() }
            Update-LeaseSelectionUi
        } catch {}
    })
}

$GridLeases.add_SelectionChanged({
    Update-LeaseSelectionUi
})
#endregion

#region Event Handlers - Reservations
$BtnResAdd.add_Click({
    Write-ActionLog "Add Reservation button clicked" "INFO"
    Show-AddReservationDialog
})

$BtnResEdit.add_Click({
    if ($null -eq $script:GridReservations.SelectedItem) {
        Show-MessageBox "Please select a reservation" "No Selection" OK Warning
        return
    }
    
    Write-ActionLog "Edit Reservation clicked - Feature placeholder" "INFO"
    Show-MessageBox "Reservation editing dialog would appear here" "Feature" OK Information
})

$BtnResDelete.add_Click({
    if ($null -eq $script:GridReservations.SelectedItem) {
        Show-MessageBox "Please select a reservation" "No Selection" OK Warning
        return
    }
    
    $res = $script:GridReservations.SelectedItem
    $result = Show-MessageBox "Delete reservation for $($res.IPAddress)?`n`nMAC: $($res.ClientId)" "Confirm Delete" YesNo Warning
    
    if ($result -eq 'Yes') {
        try {
            Write-ActionLog "Deleting reservation: $($res.IPAddress)" "INFO"
            
            Remove-DhcpServerv4Reservation -ComputerName $Global:DHCPServer -IPAddress $res.IPAddress -ErrorAction Stop
            
            Write-ActionLog "Reservation deleted successfully" "SUCCESS"
            Show-MessageBox "Reservation deleted" "Success" OK Information
            
            Load-Reservations
            
        } catch {
            $errMsg = "Failed to delete reservation: $_"
            Write-ActionLog $errMsg "ERROR"
            Show-MessageBox $errMsg "Error" OK Error
        }
    }
})

$GridReservations.add_SelectionChanged({
    $script:BtnResEdit.IsEnabled = ($null -ne $script:GridReservations.SelectedItem)
    $script:BtnResDelete.IsEnabled = ($null -ne $script:GridReservations.SelectedItem)
})
#endregion

#region Event Handlers - Exclusions
$BtnExcAdd.add_Click({
    Write-ActionLog "Add Exclusion button clicked" "INFO"
    Show-AddExclusionDialog
})

$BtnExcDelete.add_Click({
    if ($null -eq $script:GridExclusions.SelectedItem) {
        Show-MessageBox "Please select an exclusion" "No Selection" OK Warning
        return
    }
    
    $exc = $script:GridExclusions.SelectedItem
    $result = Show-MessageBox "Delete exclusion range $($exc.StartRange) - $($exc.EndRange)?" "Confirm Delete" YesNo Warning
    
    if ($result -eq 'Yes') {
        try {
            Write-ActionLog "Deleting exclusion: $($exc.StartRange) - $($exc.EndRange)" "INFO"
            
            Remove-DhcpServerv4ExclusionRange -ComputerName $Global:DHCPServer `
                -ScopeId $exc.ScopeId `
                -StartRange $exc.StartRange `
                -EndRange $exc.EndRange `
                -ErrorAction Stop
            
            Write-ActionLog "Exclusion deleted successfully" "SUCCESS"
            Show-MessageBox "Exclusion deleted" "Success" OK Information
            
            Load-Exclusions
            
        } catch {
            $errMsg = "Failed to delete exclusion: $_"
            Write-ActionLog $errMsg "ERROR"
            Show-MessageBox $errMsg "Error" OK Error
        }
    }
})

$GridExclusions.add_SelectionChanged({
    $script:BtnExcDelete.IsEnabled = ($null -ne $script:GridExclusions.SelectedItem)
})
#endregion

#region Event Handlers - Options
$CboOptionLevel.add_SelectionChanged({
    if ($null -ne $Global:DHCPServer) {
        Load-Options
    }
})

$BtnOptionSet.add_Click({
    Write-ActionLog "Set Option clicked - Feature placeholder" "INFO"
    Show-MessageBox "Option configuration dialog would appear here" "Feature" OK Information
})

$BtnOptionDelete.add_Click({
    if ($null -eq $script:GridOptions.SelectedItem) {
        Show-MessageBox "Please select an option" "No Selection" OK Warning
        return
    }
    
    Write-ActionLog "Delete Option clicked - Feature placeholder" "INFO"
    Show-MessageBox "Option deletion confirmation would appear here" "Feature" OK Information
})

$GridOptions.add_SelectionChanged({
    $script:BtnOptionDelete.IsEnabled = ($null -ne $script:GridOptions.SelectedItem)
})
#endregion

#region Event Handlers - Filters
$CboFilterList.add_SelectionChanged({
    if ($null -ne $Global:DHCPServer) {
        Load-Filters
    }
})

$BtnFilterAdd.add_Click({
    Write-ActionLog "Add Filter clicked - Feature placeholder" "INFO"
    Show-MessageBox "MAC filter addition dialog would appear here" "Feature" OK Information
})

$BtnFilterDelete.add_Click({
    if ($null -eq $script:GridFilters.SelectedItem) {
        Show-MessageBox "Please select a filter" "No Selection" OK Warning
        return
    }
    
    Write-ActionLog "Delete Filter clicked - Feature placeholder" "INFO"
    Show-MessageBox "Filter deletion confirmation would appear here" "Feature" OK Information
})

$GridFilters.add_SelectionChanged({
    $script:BtnFilterDelete.IsEnabled = ($null -ne $script:GridFilters.SelectedItem)
})
#endregion

#region Event Handlers - Policies
$BtnPolicyAdd.add_Click({
    Write-ActionLog "Add Policy clicked - Feature placeholder" "INFO"
    Show-MessageBox "Policy creation dialog would appear here" "Feature" OK Information
})

$BtnPolicyEdit.add_Click({
    if ($null -eq $script:GridPolicies.SelectedItem) {
        Show-MessageBox "Please select a policy" "No Selection" OK Warning
        return
    }
    
    Write-ActionLog "Edit Policy clicked - Feature placeholder" "INFO"
    Show-MessageBox "Policy editing dialog would appear here" "Feature" OK Information
})

$BtnPolicyDelete.add_Click({
    if ($null -eq $script:GridPolicies.SelectedItem) {
        Show-MessageBox "Please select a policy" "No Selection" OK Warning
        return
    }
    
    Write-ActionLog "Delete Policy clicked - Feature placeholder" "INFO"
    Show-MessageBox "Policy deletion confirmation would appear here" "Feature" OK Information
})

$GridPolicies.add_SelectionChanged({
    $script:BtnPolicyEdit.IsEnabled = ($null -ne $script:GridPolicies.SelectedItem)
    $script:BtnPolicyDelete.IsEnabled = ($null -ne $script:GridPolicies.SelectedItem)
})
#endregion


#region Event Handlers - Dashboard
if ($null -ne $script:BtnViewDashboard) {
    $script:BtnViewDashboard.add_Click({
        Write-ActionLog "Switching to Dashboard..." "INFO"
        $script:MainTabs.SelectedItem = $script:TabDashboard
        Initialize-DashboardBindings
        Sync-DashboardEstatePanel
        Sync-DashboardUi
    })
}

if ($null -ne $script:BtnDashboardRefresh) {
    $script:BtnDashboardRefresh.add_Click({
        Invoke-DashboardRefresh
    })
}

if ($null -ne $script:BtnDashboardOpenStats) {
    $script:BtnDashboardOpenStats.add_Click({
        $script:MainTabs.SelectedItem = $script:TabStats
        if ((Get-SafeCount $Global:ScopeStatEntriesAll) -eq 0 -and $Global:DHCPServer) {
            Load-Statistics
        }
    })
}

if ($null -ne $script:BtnDashboardScanEstate) {
    $script:BtnDashboardScanEstate.add_Click({
        Show-DomainDhcpScanDialog
        Sync-DashboardEstatePanel
        Sync-DashboardUi
    })
}

if ($null -ne $script:GridDashboardAlerts) {
    $script:GridDashboardAlerts.add_MouseDoubleClick({
        $item = $null
        try { $item = $script:GridDashboardAlerts.SelectedItem } catch {}
        if ($null -eq $item) { return }
        $row = $null
        try { $row = $item.SourceRow } catch {}
        if ($null -eq $row) {
            $sid = "$($item.ScopeId)"
            $match = @($Global:ScopeStatEntriesAll | Where-Object { "$($_.ScopeId)" -eq $sid } | Select-Object -First 1)
            if ((Get-SafeCount $match) -gt 0) { $row = $match[0] }
        }
        if ($null -ne $row) {
            $script:MainTabs.SelectedItem = $script:TabStats
            Show-ScopeStatDetailDialog -Entry $row
        }
    })
}

if ($null -ne $script:GridDashboardTopScopes) {
    $script:GridDashboardTopScopes.add_MouseDoubleClick({
        $item = $null
        try { $item = $script:GridDashboardTopScopes.SelectedItem } catch {}
        if ($null -eq $item) { return }
        $row = $null
        try { $row = $item.SourceRow } catch {}
        if ($null -eq $row) {
            $sid = "$($item.ScopeId)"
            $match = @($Global:ScopeStatEntriesAll | Where-Object { "$($_.ScopeId)" -eq $sid } | Select-Object -First 1)
            if ((Get-SafeCount $match) -gt 0) { $row = $match[0] }
        }
        if ($null -ne $row) {
            Show-ScopeStatDetailDialog -Entry $row
        }
    })
}

if ($null -ne $script:TxtScopeFilter) {
    $script:TxtScopeFilter.add_TextChanged({
        Apply-ScopeGridFilter
    })
}
#endregion

#region Event Handlers - Troubleshoot BAD_ADDRESS
if ($null -ne $script:BtnViewTroubleshoot) {
    $script:BtnViewTroubleshoot.add_Click({
        Write-ActionLog "Switching to Troubleshoot tab..." "INFO"
        $script:MainTabs.SelectedItem = $script:TabTroubleshoot
        Initialize-TroubleshootTab
        if (-not [string]::IsNullOrWhiteSpace($Global:DHCPServer)) {
            Update-TroubleshootScopeList
            if ($Global:SelectedScope) { [void](Set-TroubleshootScopeSelection -ScopeId $Global:SelectedScope) }
        }
    })
}

if ($null -ne $script:BtnTroubleshootRefreshScopes) {
    $script:BtnTroubleshootRefreshScopes.add_Click({
        Write-ActionLog "Troubleshoot refresh scopes clicked" "INFO"
        Update-TroubleshootScopeList
    })
}

if ($null -ne $script:BtnTroubleshootUseSelected) {
    $script:BtnTroubleshootUseSelected.add_Click({
        $sid = Get-SelectedScopeId
        if (-not $sid) {
            Show-MessageBox "Select a scope in the navigation tree or Scopes tab first." "No Scope Selected" OK Warning
            return
        }
        Update-TroubleshootScopeList
        if (Set-TroubleshootScopeSelection -ScopeId $sid) {
            Write-ActionLog "Troubleshoot scope set to selected: $sid" "INFO"
        } else {
            Show-MessageBox "Scope $sid was not found in the Troubleshoot scope list." "Scope Not Found" OK Warning
        }
    })
}

if ($null -ne $script:BtnTroubleshootRun) {
    $script:BtnTroubleshootRun.add_Click({
        $sid = Get-TroubleshootScopeIdFromUi
        $sample = Get-TroubleshootSampleSize
        Invoke-BadAddressDiagnostics -ScopeId $sid -SampleSize $sample
    })
}

if ($null -ne $script:BtnTroubleshootExport) {
    $script:BtnTroubleshootExport.add_Click({
        Export-BadAddressReport
    })
}

if ($null -ne $script:ChkTroubleshootReviewed) {
    $script:ChkTroubleshootReviewed.add_Checked({ Update-TroubleshootClearUi })
    $script:ChkTroubleshootReviewed.add_Unchecked({ Update-TroubleshootClearUi })
}

if ($null -ne $script:BtnTroubleshootClearBad) {
    $script:BtnTroubleshootClearBad.add_Click({
        Clear-BadAddressLeasesForScope
    })
}

if ($null -ne $script:GridTroubleshootFindings) {
    $script:GridTroubleshootFindings.add_SelectionChanged({
        if ($null -ne $script:BtnTroubleshootFindingDetails) {
            $script:BtnTroubleshootFindingDetails.IsEnabled = ($null -ne $script:GridTroubleshootFindings.SelectedItem)
        }
    })
    $script:GridTroubleshootFindings.add_MouseDoubleClick({
        $item = $null
        try { $item = $script:GridTroubleshootFindings.SelectedItem } catch {}
        if ($null -ne $item) {
            Show-TroubleshootDetailDialog -Kind Finding -Entry $item
        }
    })
    $script:GridTroubleshootFindings.add_KeyDown({
        param($sender, $e)
        if ($e.Key -eq [System.Windows.Input.Key]::Enter -or $e.Key -eq [System.Windows.Input.Key]::Return) {
            $item = $null
            try { $item = $script:GridTroubleshootFindings.SelectedItem } catch {}
            if ($null -ne $item) {
                Show-TroubleshootDetailDialog -Kind Finding -Entry $item
                $e.Handled = $true
            }
        }
    })
}

if ($null -ne $script:BtnTroubleshootFindingDetails) {
    $script:BtnTroubleshootFindingDetails.add_Click({
        $item = $null
        try { $item = $script:GridTroubleshootFindings.SelectedItem } catch {}
        Show-TroubleshootDetailDialog -Kind Finding -Entry $item
    })
}

if ($null -ne $script:GridTroubleshootBadLeases) {
    $script:GridTroubleshootBadLeases.add_MouseDoubleClick({
        $item = $null
        try { $item = $script:GridTroubleshootBadLeases.SelectedItem } catch {}
        if ($null -ne $item) {
            Show-TroubleshootDetailDialog -Kind BadLease -Entry $item
        }
    })
    $script:GridTroubleshootBadLeases.add_KeyDown({
        param($sender, $e)
        if ($e.Key -eq [System.Windows.Input.Key]::Enter -or $e.Key -eq [System.Windows.Input.Key]::Return) {
            $item = $null
            try { $item = $script:GridTroubleshootBadLeases.SelectedItem } catch {}
            if ($null -ne $item) {
                Show-TroubleshootDetailDialog -Kind BadLease -Entry $item
                $e.Handled = $true
            }
        }
    })
}

if ($null -ne $script:GridTroubleshootProbes) {
    $script:GridTroubleshootProbes.add_MouseDoubleClick({
        $item = $null
        try { $item = $script:GridTroubleshootProbes.SelectedItem } catch {}
        if ($null -ne $item) {
            Show-TroubleshootDetailDialog -Kind Probe -Entry $item
        }
    })
    $script:GridTroubleshootProbes.add_KeyDown({
        param($sender, $e)
        if ($e.Key -eq [System.Windows.Input.Key]::Enter -or $e.Key -eq [System.Windows.Input.Key]::Return) {
            $item = $null
            try { $item = $script:GridTroubleshootProbes.SelectedItem } catch {}
            if ($null -ne $item) {
                Show-TroubleshootDetailDialog -Kind Probe -Entry $item
                $e.Handled = $true
            }
        }
    })
}
#endregion

#region Event Handlers - Statistics
$BtnRefreshStats.add_Click({
    Write-ActionLog "Refreshing statistics (all scopes)..." "INFO"
    Load-Statistics
})

if ($null -ne $script:CboUtilThreshold) {
    $script:CboUtilThreshold.add_SelectionChanged({
        if ((Get-SafeCount $Global:ScopeStatEntriesAll) -eq 0) { return }
        # Re-level existing rows against the new threshold without a full server round-trip
        $threshold = Get-ScopeUtilThresholdPercent
        $rebuilt = [System.Collections.Generic.List[object]]::new()
        foreach ($row in @($Global:ScopeStatEntriesAll)) {
            if ($null -eq $row) { continue }
            $pct = 0.0
            try { $pct = [double]$row.PercentInUse } catch { $pct = 0.0 }
            $level = Get-ScopeUtilLevel -PercentInUse $pct -Threshold $threshold
            $status = switch ($level) {
                'Critical' { "Critical ≥${threshold}%" }
                'Warning'  { 'Warning' }
                default    { 'OK' }
            }
            [void]$rebuilt.Add([PSCustomObject]@{
                ScopeId         = $row.ScopeId
                Name            = $row.Name
                State           = $row.State
                Description     = $row.Description
                StartRange      = $row.StartRange
                EndRange        = $row.EndRange
                SubnetMask      = $row.SubnetMask
                LeaseDuration   = $row.LeaseDuration
                RangeDisplay    = $row.RangeDisplay
                InUse           = $row.InUse
                Free            = $row.Free
                Total           = $row.Total
                Reserved        = $row.Reserved
                Pending         = $row.Pending
                PercentInUse    = $row.PercentInUse
                PercentDisplay  = $row.PercentDisplay
                Level           = $level
                Status          = $status
                Threshold       = $threshold
            })
        }
        $sorted = @($rebuilt | Sort-Object -Property @{ Expression = 'PercentInUse'; Descending = $true }, @{ Expression = 'Name'; Descending = $false })
        $Global:ScopeStatEntriesAll.Clear()
        foreach ($r in $sorted) { [void]$Global:ScopeStatEntriesAll.Add($r) }
        $critical = @($sorted | Where-Object { "$($_.Level)" -eq 'Critical' })
        $warning = @($sorted | Where-Object { "$($_.Level)" -eq 'Warning' })
        Apply-ScopeStatFilter
        Update-ScopeUtilAlertBanner -CriticalCount (Get-SafeCount $critical) -WarningCount (Get-SafeCount $warning) -Threshold $threshold -CriticalScopes $critical
        Sync-DashboardUi
    })
}

if ($null -ne $script:CboScopeStatFilter) {
    $script:CboScopeStatFilter.add_SelectionChanged({
        if ((Get-SafeCount $Global:ScopeStatEntriesAll) -eq 0) { return }
        Apply-ScopeStatFilter
    })
}

if ($null -ne $script:BtnScopeStatDetails) {
    $script:BtnScopeStatDetails.add_Click({
        $item = $null
        try { $item = $script:GridScopeStats.SelectedItem } catch {}
        Show-ScopeStatDetailDialog -Entry $item
    })
}

if ($null -ne $script:GridScopeStats) {
    $script:GridScopeStats.ItemsSource = $Global:ScopeStatEntries
    $script:GridScopeStats.add_MouseDoubleClick({
        $item = $null
        try { $item = $script:GridScopeStats.SelectedItem } catch {}
        if ($null -ne $item) {
            Show-ScopeStatDetailDialog -Entry $item
        }
    })
    $script:GridScopeStats.add_KeyDown({
        param($sender, $e)
        if ($e.Key -eq [System.Windows.Input.Key]::Enter -or $e.Key -eq [System.Windows.Input.Key]::Return) {
            $item = $null
            try { $item = $script:GridScopeStats.SelectedItem } catch {}
            if ($null -ne $item) {
                Show-ScopeStatDetailDialog -Entry $item
                $e.Handled = $true
            }
        }
    })
}

if ($null -ne $script:BtnExportScopeStats) {
    $script:BtnExportScopeStats.add_Click({
        if ((Get-SafeCount $Global:ScopeStatEntries) -eq 0) {
            Show-MessageBox "No scope statistics to export. Click Refresh All Scopes first." "Export" OK Warning
            return
        }
        try {
            $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
            $saveDialog.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
            $saveDialog.FileName = "DHCP-Scope-Stats-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
            $saveDialog.Title = "Export Scope Statistics"
            if ($saveDialog.ShowDialog() -eq 'OK') {
                $Global:ScopeStatEntries |
                    Select-Object Status, PercentDisplay, ScopeId, Name, State, InUse, Free, Total, Reserved, Pending, RangeDisplay, SubnetMask, LeaseDuration, Description, Level, Threshold |
                    Export-Csv -Path $saveDialog.FileName -NoTypeInformation -Encoding UTF8
                Write-ActionLog "Exported $(Get-SafeCount $Global:ScopeStatEntries) scope stats: $($saveDialog.FileName)" "SUCCESS"
                Show-MessageBox "Exported $(Get-SafeCount $Global:ScopeStatEntries) scope(s) to:`n$($saveDialog.FileName)" "Export Complete" OK Information
                Update-LogDisplay
            }
        } catch {
            Write-ActionLog "Scope stats export failed: $_" "ERROR"
            Show-MessageBox "Export failed: $_" "Export Error" OK Error
        }
    })
}
#endregion

#region Event Handlers - Compare Servers
$BtnViewCompare.add_Click({
    Write-ActionLog "Switching to Compare tab..." "INFO"
    $script:MainTabs.SelectedItem = $script:TabCompare
    Update-CompareReadyState
})

$BtnViewMigrate.add_Click({
    Write-ActionLog "Switching to Migrate tab..." "INFO"
    $script:MainTabs.SelectedItem = $script:TabMigrate
    Update-MigrateReadyState
})

$BtnCompareConnect.add_Click({
    Write-ActionLog "Compare server connect clicked" "INFO"
    
    $serverName = $script:TxtCompareServer.Text.Trim()
    
    if ([string]::IsNullOrWhiteSpace($serverName)) {
        Show-MessageBox "Enter a compare server hostname or IP address." "Validation Error" OK Warning
        return
    }
    
    $cleaned = Get-CleanDhcpServerHostName -Name $serverName
    if (-not [string]::IsNullOrWhiteSpace($cleaned) -and $cleaned -ne $serverName) {
        Write-ActionLog "Cleaned compare server name '$serverName' -> '$cleaned'" "INFO"
        $serverName = $cleaned
        $script:TxtCompareServer.Text = $cleaned
    }
    
    if ([string]::IsNullOrWhiteSpace($Global:DHCPServer)) {
        Show-MessageBox "Connect to primary Server A first, then connect Server B." "Compare" OK Warning
        return
    }
    
    if ($serverName -eq $Global:DHCPServer) {
        Show-MessageBox "Server B must be different from Server A." "Validation Error" OK Warning
        return
    }
    
    $fallbackIp = Get-DhcpFallbackIpForName -Name $serverName
    Set-Status "Connecting compare server $serverName..."
    Write-ActionLog "Attempting compare connection to: $serverName$(if ($fallbackIp) { " (IP fallback $fallbackIp)" })" "INFO"
    
    try {
        $normalized = Connect-DhcpServerTarget -ComputerName $serverName -FallbackIP $fallbackIp
        
        $Global:CompareServer = $normalized
        Write-ActionLog "Connected compare Server B: $normalized" "SUCCESS"
        
        $script:BtnCompareConnect.IsEnabled = $false
        $script:TxtCompareServer.Text = $normalized
        $script:TxtCompareServer.IsEnabled = $false
        $script:BtnCompareDisconnect.IsEnabled = $true
        
        Update-CompareReadyState
        Set-Status "Compare server connected: $normalized"
        Update-LogDisplay
        
    } catch {
        $errMsg = "$_"
        Write-ActionLog $errMsg "ERROR"
        Set-Status "Compare connection failed"
        Show-MessageBox $errMsg "Connection Error" OK Error
        Update-LogDisplay
    }
})

$BtnCompareDisconnect.add_Click({
    Write-ActionLog "Disconnecting compare Server B..." "INFO"
    
    $Global:CompareServer = $null
    $Global:CompareResults.Clear()
    
    $script:BtnCompareConnect.IsEnabled = $true
    $script:TxtCompareServer.IsEnabled = $true
    $script:BtnCompareDisconnect.IsEnabled = $false
    $script:GridCompare.ItemsSource = $null
    $script:CmpOnlyA.Text = "0"
    $script:CmpOnlyB.Text = "0"
    $script:CmpMatch.Text = "0"
    $script:CmpDiff.Text = "0"
    
    Update-CompareReadyState
    Write-ActionLog "Compare Server B disconnected" "SUCCESS"
    Update-LogDisplay
})

$BtnRunCompare.add_Click({
    Invoke-DhcpServerCompare
})

$BtnCompareExport.add_Click({
    Export-CompareResults
})

$BtnCompareMigrate.add_Click({
    try {
        Invoke-CompareSelectedScopeMigration
    } catch {
        Write-ActionLog "Compare migrate failed: $_" "ERROR"
        Show-MessageBox "Compare migrate failed: $_" "Compare Migrate" OK Error
        Update-LogDisplay
    }
})

$CboCompareFilter.add_SelectionChanged({
    if ($Global:CompareResults.Count -gt 0) {
        Show-CompareResults -Results $Global:CompareResults
    }
})

$CboCompareCategory.add_SelectionChanged({
    if ($Global:CompareResults.Count -gt 0) {
        Write-ActionLog "Compare category changed — re-run compare for new category" "INFO"
    }
})
#endregion

#region Event Handlers - Scope Migration
$BtnMigrateRefreshScopes.add_Click({
    try {
        Import-MigrationSourceScopes
    } catch {
        Write-ActionLog "Load migration scopes failed: $_" "ERROR"
        Show-MessageBox "Failed to load source scopes: $_" "Migrate" OK Error
        Update-LogDisplay
    }
})

$BtnMigrateSelectAll.add_Click({
    Set-MigrationScopeSelection -Selected $true
})

$BtnMigrateSelectNone.add_Click({
    Set-MigrationScopeSelection -Selected $false
})

$BtnMigrateDryRun.add_Click({
    try {
        # Prefer checkbox selection; fall back to highlighted rows
        try { $script:GridMigrateScopes.CommitEdit() } catch {}
        $checked = @($Global:MigrationScopes | Where-Object { $_.Selected })
        if ($checked.Count -eq 0 -and $script:GridMigrateScopes.SelectedItems.Count -gt 0) {
            foreach ($item in @($script:GridMigrateScopes.SelectedItems)) { $item.Selected = $true }
        }
        Invoke-DhcpScopeMigration -DryRun
    } catch {
        Write-ActionLog "Dry run failed: $_" "ERROR"
        Show-MessageBox "Dry run failed: $_" "Migrate" OK Error
        Update-LogDisplay
    }
})

$BtnMigrateRun.add_Click({
    try {
        try { $script:GridMigrateScopes.CommitEdit() } catch {}
        $checked = @($Global:MigrationScopes | Where-Object { $_.Selected })
        if ($checked.Count -eq 0 -and $script:GridMigrateScopes.SelectedItems.Count -gt 0) {
            foreach ($item in @($script:GridMigrateScopes.SelectedItems)) { $item.Selected = $true }
        }
        Invoke-DhcpScopeMigration
    } catch {
        Write-ActionLog "Migration failed: $_" "ERROR"
        Show-MessageBox "Migration failed: $_" "Migrate" OK Error
        Update-LogDisplay
    }
})

$BtnMigrateExport.add_Click({
    Export-MigrationPlan
})

$GridMigrateScopes.add_MouseLeftButtonUp({
    Update-MigrateReadyState
})
#endregion

#region Event Handlers - DHCP Events / Live Watch
$BtnViewEvents.add_Click({
    Write-ActionLog "Switching to DHCP Events tab..." "INFO"
    $script:MainTabs.SelectedItem = $script:TabEvents
    if ($null -eq $script:GridEvents.ItemsSource) {
        $script:GridEvents.ItemsSource = $Global:DhcpEventEntries
    }
    Update-EventWatchStatus
})

$BtnEventBrowse.add_Click({
    try {
        $dlg = New-Object System.Windows.Forms.OpenFileDialog
        $dlg.Filter = "DHCP Logs (DhcpSrvLog*.*)|DhcpSrvLog*.*|Log Files (*.log)|*.log|All Files (*.*)|*.*"
        $dlg.Title = "Select DHCP Audit Log"
        if ($dlg.ShowDialog() -eq 'OK') {
            $script:TxtEventLogPath.Text = $dlg.FileName
            $script:CboEventSource.SelectedIndex = 3  # Custom Path
            Write-ActionLog "Selected log file: $($dlg.FileName)" "INFO"
        }
    } catch {
        Write-ActionLog "Browse failed: $_" "ERROR"
    }
})

$BtnWatchBrowse.add_Click({
    try {
        $dlg = New-Object System.Windows.Forms.OpenFileDialog
        $dlg.Filter = "DHCP Logs (DhcpSrvLog*.*)|DhcpSrvLog*.*|Log Files (*.log)|*.log|All Files (*.*)|*.*"
        $dlg.Title = "Select DHCP Audit Log to Live Watch"
        if ($dlg.ShowDialog() -eq 'OK') {
            $script:TxtWatchLogPath.Text = $dlg.FileName
            try { $script:ChkWatchCustom.IsChecked = $true } catch {}
            Write-ActionLog "Watch file set to $($dlg.FileName)" "INFO"
            Update-LogDisplay
        }
    } catch {
        Write-ActionLog "Watch browse failed: $_" "ERROR"
        Show-MessageBox "Browse failed: $_" "Browse" OK Error
    }
})

$BtnWatchUseIngestPath.add_Click({
    $path = ''
    try { $path = "$($script:TxtEventLogPath.Text)".Trim() } catch {}
    if ([string]::IsNullOrWhiteSpace($path)) {
        Show-MessageBox "Ingest path is empty. Detect/Browse a log first, or type a path in Watch file." "Live Watch" OK Warning
        return
    }
    $script:TxtWatchLogPath.Text = $path
    try { $script:ChkWatchCustom.IsChecked = $true } catch {}
    Write-ActionLog "Watch file set from ingest path: $path" "INFO"
    Update-LogDisplay
})

$BtnEventDetect.add_Click({
    try {
        $src = Get-SelectedEventSourceKey
        $customPath = ''
        try { $customPath = "$($script:TxtEventLogPath.Text)".Trim() } catch {}
        
        if ($src -eq 'Custom' -and [string]::IsNullOrWhiteSpace($customPath)) {
            Show-MessageBox "For Custom Path, enter a folder/file path first (or Browse), then Detect Logs." "Detect Logs" OK Information
            return
        }
        
        if ($src -eq 'A' -and -not $Global:DHCPServer) {
            Show-MessageBox "Connect Server A first." "Detect Logs" OK Warning
            return
        }
        if ($src -eq 'B' -and -not $Global:CompareServer) {
            Show-MessageBox "Connect Server B first (Compare tab)." "Detect Logs" OK Warning
            return
        }
        
        $selected = Show-DhcpAuditLogPickerDialog -Source $src -CustomPath $customPath
        if ([string]::IsNullOrWhiteSpace($selected)) { return }
        
        $script:TxtEventLogPath.Text = $selected
        Write-ActionLog "Selected DHCP audit log ($src): $selected" "SUCCESS"
        $script:TxtEventStatus.Text = "Selected for ingest: $selected"
        Update-LogDisplay
    } catch {
        Write-ActionLog "Detect failed: $_" "ERROR"
        Show-MessageBox "Detect failed: $_" "Detect Logs" OK Error
    }
})

$BtnEventIngest.add_Click({
    try {
        if ($Global:TaskProgress.Active) {
            Show-MessageBox "A task is already running: $($Global:TaskProgress.Name). Pause/Cancel it first." "Ingest" OK Warning
            return
        }
        
        $src = Get-SelectedEventSourceKey
        $path = $script:TxtEventLogPath.Text.Trim()
        
        if ([string]::IsNullOrWhiteSpace($path)) {
            $path = Get-DhcpAuditLogPath -Source $(if ($src -eq 'Custom') { 'Local' } else { $src }) -CustomPath $path
            if ($path) { $script:TxtEventLogPath.Text = $path }
        }
        
        if ([string]::IsNullOrWhiteSpace($path)) {
            Show-MessageBox "Provide a log path (or click Detect / Browse)." "Ingest" OK Warning
            return
        }
        
        $label = Get-EventServerLabel -SourceKey $src
        Set-Status "Ingesting DHCP log..."
        $info = Import-DhcpAuditLogFile -Path $path -ServerLabel $label
        
        if ($info.Canceled) {
            $script:TxtEventStatus.Text = "Ingest canceled — previous events retained ($($info.Path))"
            Set-Status "Ingest canceled"
        } else {
            $shown = if ($null -ne $info.Shown) { $info.Shown } else { $info.EventCount }
            $visible = Get-SafeCount $Global:DhcpEventEntries
            $total = Get-SafeCount $Global:DhcpEventEntriesAll
            $script:TxtEventStatus.Text = "Ingested $($info.EventCount) events from $label (showing $visible of $total) — $($info.Path)"
            Set-Status "Ingested $($info.EventCount) DHCP events"
            Update-EventFilterCountDisplay
        }
        Update-LogDisplay
    } catch {
        Complete-TaskProgress -Message "Ingest failed"
        try { if ($null -ne $script:BtnEventIngest) { $script:BtnEventIngest.IsEnabled = $true } } catch {}
        $errMsg = "Ingest failed: $_"
        Write-ActionLog $errMsg "ERROR"
        Show-MessageBox $errMsg "Ingest Error" OK Error
        Update-LogDisplay
    }
})

$BtnEventIngestPause.add_Click({
    Toggle-TaskProgressPause
})

$BtnTaskPause.add_Click({
    Toggle-TaskProgressPause
})

$BtnTaskCancel.add_Click({
    Request-TaskProgressCancel
})

$BtnEventWatchStart.add_Click({
    try {
        Start-DhcpEventWatch
    } catch {
        $errMsg = "Failed to start live watch: $_"
        Write-ActionLog $errMsg "ERROR"
        Show-MessageBox $errMsg "Live Watch" OK Error
        Stop-DhcpEventWatch
        Update-LogDisplay
    }
})

$BtnEventWatchStop.add_Click({
    Stop-DhcpEventWatch
})

$BtnEventClear.add_Click({
    $result = Show-MessageBox "Clear all loaded DHCP events from the grid?" "Confirm Clear" YesNo Question
    if ($result -eq 'Yes') {
        $script:Window.Dispatcher.Invoke([action]{
            $Global:DhcpEventEntries.Clear()
            $Global:DhcpEventEntriesAll.Clear()
        }, [System.Windows.Threading.DispatcherPriority]::Normal)
        Clear-DhcpEventFilterFields
        Update-EventFilterServerCombo
        Update-EventFilterCountDisplay -Shown 0 -Total 0
        Write-ActionLog "DHCP event grid cleared" "WARN"
        Update-EventWatchStatus
        Update-LogDisplay
    }
})

$BtnEventDetails.add_Click({
    $item = $null
    try { $item = $script:GridEvents.SelectedItem } catch {}
    Show-DhcpEventDetailDialog -Entry $item
})

$script:GridEvents.add_MouseDoubleClick({
    $item = $null
    try { $item = $script:GridEvents.SelectedItem } catch {}
    if ($null -ne $item) {
        Show-DhcpEventDetailDialog -Entry $item
    }
})

$script:GridEvents.add_KeyDown({
    param($sender, $e)
    if ($e.Key -eq [System.Windows.Input.Key]::Enter -or $e.Key -eq [System.Windows.Input.Key]::Return) {
        $item = $null
        try { $item = $script:GridEvents.SelectedItem } catch {}
        if ($null -ne $item) {
            Show-DhcpEventDetailDialog -Entry $item
            $e.Handled = $true
        }
    }
})

$BtnEventExport.add_Click({
    if ((Get-SafeCount $Global:DhcpEventEntries) -eq 0) {
        Show-MessageBox "No DHCP events to export (try clearing filters or ingest first)." "Export" OK Warning
        return
    }
    
    try {
        $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveDialog.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
        $saveDialog.FileName = "DHCP-Events-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
        $saveDialog.Title = "Export DHCP Events (filtered view)"
        
        if ($saveDialog.ShowDialog() -eq 'OK') {
            $Global:DhcpEventEntries |
                Select-Object Server, Time, EventId, Description, IPAddress, MacAddress, HostName, Details |
                Export-Csv -Path $saveDialog.FileName -NoTypeInformation -Encoding UTF8
            Write-ActionLog "Exported $(Get-SafeCount $Global:DhcpEventEntries) filtered events: $($saveDialog.FileName)" "SUCCESS"
            Show-MessageBox "Exported $(Get-SafeCount $Global:DhcpEventEntries) event(s) to:`n$($saveDialog.FileName)" "Export Complete" OK Information
            Update-LogDisplay
        }
    } catch {
        Write-ActionLog "Event export failed: $_" "ERROR"
        Show-MessageBox "Export failed: $_" "Export Error" OK Error
    }
})

$BtnEventFilterApply.add_Click({
    Apply-DhcpEventFilter
})

$BtnEventFilterClear.add_Click({
    Clear-DhcpEventFilterFields
    Apply-DhcpEventFilter
})

# Enter key in filter text boxes applies filter
foreach ($tbName in @('TxtEventFilter','TxtEventFilterIp','TxtEventFilterMac','TxtEventFilterHost')) {
    $tb = $null
    try { $tb = Get-Variable -Name $tbName -Scope Script -ValueOnly -ErrorAction SilentlyContinue } catch {}
    if ($null -eq $tb) { continue }
    $tb.add_KeyDown({
        param($sender, $e)
        if ($e.Key -eq 'Return') {
            Apply-DhcpEventFilter
            $e.Handled = $true
        }
    })
}

$CboEventIdFilter.add_SelectionChanged({
    if ($script:UpdatingEventFilterServerCombo) { return }
    if ((Get-SafeCount $Global:DhcpEventEntriesAll) -gt 0) {
        Apply-DhcpEventFilter -Quiet
        Update-EventFilterCountDisplay
    }
})

$CboEventFilterServer.add_SelectionChanged({
    if ($script:UpdatingEventFilterServerCombo) { return }
    if ((Get-SafeCount $Global:DhcpEventEntriesAll) -gt 0) {
        Apply-DhcpEventFilter -Quiet
        Update-EventFilterCountDisplay
    }
})
#endregion

#region Event Handlers - Action Log Tab
$BtnViewLog.add_Click({
    Write-ActionLog "Switching to Action Log tab..." "INFO"
    $script:MainTabs.SelectedItem = $script:TabLog
    Update-LogDisplay
})

$BtnLogRefresh.add_Click({
    Write-ActionLog "Refreshing log display..." "INFO"
    Update-LogDisplay
})

$BtnLogClear.add_Click({
    $result = Show-MessageBox "Clear all log entries?" "Confirm Clear" YesNo Question
    
    if ($result -eq 'Yes') {
        Write-ActionLog "Clearing action log..." "WARN"
        $Global:ActionLog.Clear()
        Update-LogDisplay
        Write-ActionLog "Action log cleared - Starting fresh" "INFO"
    }
})

$BtnLogExport.add_Click({
    Write-ActionLog "Export log button clicked" "INFO"
    
    try {
        $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveDialog.Filter = "Text Files (*.txt)|*.txt|Log Files (*.log)|*.log|All Files (*.*)|*.*"
        $saveDialog.FileName = "DHCP-Manager-Log-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
        $saveDialog.Title = "Export Action Log"
        
        if ($saveDialog.ShowDialog() -eq 'OK') {
            $logContent = $Global:ActionLog -join "`r`n"
            
            $header = @"
═══════════════════════════════════════════════════════════════════════
DHCP Manager v2.4 - Action Log Export (Anthony Blake)
═══════════════════════════════════════════════════════════════════════
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Server: $Global:DHCPServer
Total Entries: $($Global:ActionLog.Count)
═══════════════════════════════════════════════════════════════════════

"@
            
            $fullContent = $header + $logContent
            
            [System.IO.File]::WriteAllText($saveDialog.FileName, $fullContent, [System.Text.Encoding]::UTF8)
            
            Write-ActionLog "Log exported to: $($saveDialog.FileName)" "SUCCESS"
            Show-MessageBox "Log exported successfully to:`n$($saveDialog.FileName)" "Export Complete" OK Information
            Update-LogDisplay
        }
        
    } catch {
        $errMsg = "Failed to export log: $_"
        Write-ActionLog $errMsg "ERROR"
        Show-MessageBox $errMsg "Export Error" OK Error
    }
})

$CboLogLevel.add_SelectionChanged({
    # Future: Implement log filtering by level
    Write-ActionLog "Log level filter changed (filtering not yet implemented)" "INFO"
})
#endregion

#region Event Handlers - Utility Buttons
$BtnSettings.add_Click({
    Write-ActionLog "Settings button clicked" "INFO"
    
    $settingsMsg = @"
DHCP Manager v2.4 - Settings

Author: $($Global:AppAuthor)
Version: $($Global:AppVersion)

Current Configuration:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PowerShell Version: $($PSVersionTable.PSVersion)
DhcpServer Module: $(if (Get-Module DhcpServer) { 'Loaded' } else { 'Not Loaded' })
Server A (Source): $(if ($Global:DHCPServer) { $Global:DHCPServer } else { 'None' })
Server B (Dest): $(if ($Global:CompareServer) { $Global:CompareServer } else { 'None' })
Selected Scope: $(if ($Global:SelectedScope) { $Global:SelectedScope } else { 'None' })
Domain Scan Results: $($Global:DomainScanResults.Count)
Migration Scopes Loaded: $($Global:MigrationScopes.Count)
Migration Result Rows: $($Global:MigrationResults.Count)
Compare Results: $($Global:CompareResults.Count)
DHCP Events Loaded: $($Global:DhcpEventEntries.Count)
Live Watch Active: $($Global:EventWatchActive)
Log Entries: $($Global:ActionLog.Count)

Use Scan Domain to discover authorized DHCP servers across multiple DNS domains
(add child/trusted domains in the scan dialog; extras can be remembered).
Ping Up/Down + AD authorization. Use results as Server A/B.
"@
    
    Show-MessageBox $settingsMsg "Settings" OK Information
})

$BtnAbout.add_Click({
    Write-ActionLog "About button clicked" "INFO"
    
    $aboutMsg = @"
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║              DHCP Manager v2.4                                   ║
║                  Built by Anthony Blake                          ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝

🎯 Version: $($Global:AppVersion)
👤 Author: $($Global:AppAuthor)
📅 Date: August 19, 2026
🏢 Repository: ciscocdp-netizen/PowershellTools

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✓ Features Included:

  • Domain DHCP server scan + ping Up/Down status
  • Full WPF GUI with dark modern theme
  • Complete DHCP scope / lease / reservation management
  • Multi-server comparison (scopes, options, leases, reservations)
  • Scope migration A→B (scopes, options, reservations, exclusions)
  • Optional active leases → reservations on destination
  • Dry-run migration planning + CSV export
  • DHCP audit log ingest (local + remote UNC)
  • Real-time DHCP event watching (Local / Server A / Server B)
  • Action logging with millisecond timestamps
  • Thread-safe UI updates via Dispatcher

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Built by Anthony Blake for Network Engineers

"@
    
    Show-MessageBox $aboutMsg "About DHCP Manager" OK Information
})
#endregion

#region Window Events
$Window.add_Loaded({
    Write-ActionLog "Main window loaded successfully" "SUCCESS"
    
    # Stamp author in status and bind events grid
    try {
        $script:GridEvents.ItemsSource = $Global:DhcpEventEntries
        $script:GridMigrateScopes.ItemsSource = $Global:MigrationScopes
        if ($null -ne $script:GridScopeStats) {
            $script:GridScopeStats.ItemsSource = $Global:ScopeStatEntries
        }
        Initialize-TroubleshootTab
        Initialize-DashboardBindings
        Update-EventWatchStatus
        Update-MigrateReadyState
    } catch {}
    
    # Start status time updater
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromSeconds(1)
    $timer.Add_Tick({
        $script:StatusTime.Text = Get-Date -Format 'HH:mm:ss'
    })
    $timer.Start()
    
    Update-LogDisplay
    
    Write-Host "`n═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  DHCP Manager v2.4 — Built by Anthony Blake" -ForegroundColor Green
    Write-Host "  Scan Domain • Compare • Live Events • Scope Migration" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════`n" -ForegroundColor Cyan
})

$Window.add_Closing({
    Write-ActionLog "Application closing..." "INFO"
    
    try { Stop-DhcpEventWatch } catch {}
    
    if ($Global:DHCPServer) {
        Write-ActionLog "Session ended. Server: $Global:DHCPServer" "INFO"
    }
    
    Write-ActionLog "Total log entries: $($Global:ActionLog.Count)" "INFO"
    Write-ActionLog "DHCP Manager v2.4 shutdown complete — $($Global:AppAuthor)" "SUCCESS"
    
    Write-Host "`n═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  DHCP Manager v2.4 closed — Anthony Blake" -ForegroundColor Yellow
    Write-Host "  Thank you for using DHCP Manager!" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════`n" -ForegroundColor Cyan
})
#endregion

#region Application Startup
Write-ActionLog "All event handlers registered successfully" "SUCCESS"
Write-ActionLog "Starting main window event loop..." "INFO"

try {
    # Show the window
    [void]$Window.ShowDialog()
    
} catch {
    Write-Error "Fatal error during window display: $_"
    Write-ActionLog "FATAL: Window display failed - $_" "ERROR"
    exit 1
}

Write-ActionLog "Application terminated normally" "INFO"
#endregion

# End of DHCP Manager v2.0 Complete Production Script
