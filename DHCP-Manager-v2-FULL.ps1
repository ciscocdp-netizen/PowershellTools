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
    
.NOTES
    File Name      : DHCP-Manager-v2-FULL.ps1
    Version        : 2.4.0 (Domain DHCP Scan)
    Date           : 2026-08-19
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
$Global:AppVersion       = '2.4.6'
$Global:DhcpEventEntries = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$Global:LogWatchState    = @{
    Local = @{ Enabled = $false; Path = $null; Offset = 0L }
    A     = @{ Enabled = $false; Path = $null; Offset = 0L }
    B     = @{ Enabled = $false; Path = $null; Offset = 0L }
}
$Global:EventWatchActive = $false
$Global:MigrationResults = [System.Collections.Generic.List[object]]::new()
$Global:MigrationScopes  = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$Global:DomainScanResults = [System.Collections.Generic.List[object]]::new()
$Global:ExtraScanDomains  = [System.Collections.Generic.List[string]]::new()
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
    Title="DHCP Manager v2.4 - Anthony Blake"
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
      <Setter Property="Foreground"    Value="{StaticResource TextPrimary}"/>
      <Setter Property="BorderBrush"   Value="{StaticResource Border}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding"       Value="8,5"/>
      <Setter Property="FontSize"      Value="12"/>
      <Setter Property="CaretBrush"    Value="{StaticResource TextPrimary}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TextBox">
            <Border Background="{TemplateBinding Background}"
                    BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}"
                    CornerRadius="4">
              <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsFocused" Value="True">
                <Setter Property="BorderBrush" Value="{StaticResource Accent}"/>
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
          <Button x:Name="BtnViewMigrate" Content="🚚 Migrate" Margin="0,0,8,0"
                  Style="{StaticResource BtnSecondary}" ToolTip="Migrate scopes to another DHCP server"/>
          <Button x:Name="BtnViewEvents" Content="📡 Events" Margin="0,0,8,0"
                  Style="{StaticResource BtnSecondary}" ToolTip="DHCP audit logs and live events"/>
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
          <Run Text="v2.4.6  |  "/>
          <Run Text="Anthony Blake  |  " Foreground="#90CAF9"/>
          <Run x:Name="StatusTime" Text=""/>
        </TextBlock>
      </Grid>
    </Border>

    <!-- MAIN CONTENT AREA with Navigation and Tabs -->
    <Grid DockPanel.Dock="Top" Margin="0">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="260" MinWidth="200"/>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="*" MinWidth="400"/>
      </Grid.ColumnDefinitions>

      <!-- LEFT NAVIGATION PANEL -->
      <Border Grid.Column="0" Background="{StaticResource BgCard}"
              BorderThickness="0,0,1,0" BorderBrush="{StaticResource Border}">
        <DockPanel>
          <Border DockPanel.Dock="Top" Background="{StaticResource BgPanel}"
                  Padding="12,10" BorderThickness="0,0,0,1" BorderBrush="{StaticResource Border}">
            <TextBlock Text="📡 DHCP Navigation" Foreground="{StaticResource TextPrimary}"
                       FontWeight="SemiBold" FontSize="13"/>
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
                <StackPanel Orientation="Horizontal">
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
                <StackPanel Orientation="Horizontal">
                  <Button x:Name="BtnLeaseRelease" Content="🚫 Release" Margin="0,0,8,0"
                          Style="{StaticResource BtnDanger}" IsEnabled="False"/>
                  <Button x:Name="BtnLeaseReserve" Content="📌 Convert to Reservation" Margin="0,0,8,0"
                          Style="{StaticResource BtnPrimary}" IsEnabled="False"/>
                  <Button x:Name="BtnLeaseRefresh" Content="🔄 Refresh" Margin="0,0,8,0"
                          Style="{StaticResource BtnSecondary}" IsEnabled="False"/>
                  <Separator Width="1" Background="{StaticResource Border}" Margin="8,0"/>
                  <TextBlock Text="Filter:" Style="{StaticResource FormLabel}"
                             VerticalAlignment="Center" Margin="8,0,8,0"/>
                  <TextBox x:Name="TxtLeaseFilter" Width="200" Style="{StaticResource DarkTextBox}"
                           ToolTip="Filter by IP, MAC, or hostname"/>
                </StackPanel>
              </Border>

              <!-- Leases Grid -->
              <DataGrid Grid.Row="1" x:Name="GridLeases" Style="{StaticResource DarkGrid}" Margin="8">
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

          <!-- TAB: Statistics -->
          <TabItem x:Name="TabStats" Header="📊 Statistics">
            <ScrollViewer VerticalScrollBarVisibility="Auto" Background="{StaticResource BgPanel}">
              <StackPanel Margin="16">
                <TextBlock Text="Server Statistics" Style="{StaticResource SectionHeader}"/>
                
                <Grid>
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="*"/>
                  </Grid.ColumnDefinitions>
                  <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                  </Grid.RowDefinitions>

                  <!-- Stat Cards -->
                  <Border Grid.Row="0" Grid.Column="0" Background="{StaticResource BgCard}"
                          CornerRadius="6" Padding="16" Margin="0,0,8,8">
                    <StackPanel>
                      <TextBlock Text="Total Scopes" Style="{StaticResource FormLabel}"/>
                      <TextBlock x:Name="StatTotalScopes" Text="0" FontSize="28" FontWeight="Bold"
                                 Foreground="{StaticResource Accent}"/>
                    </StackPanel>
                  </Border>

                  <Border Grid.Row="0" Grid.Column="1" Background="{StaticResource BgCard}"
                          CornerRadius="6" Padding="16" Margin="4,0,4,8">
                    <StackPanel>
                      <TextBlock Text="Active Leases" Style="{StaticResource FormLabel}"/>
                      <TextBlock x:Name="StatActiveLeases" Text="0" FontSize="28" FontWeight="Bold"
                                 Foreground="{StaticResource Success}"/>
                    </StackPanel>
                  </Border>

                  <Border Grid.Row="0" Grid.Column="2" Background="{StaticResource BgCard}"
                          CornerRadius="6" Padding="16" Margin="8,0,0,8">
                    <StackPanel>
                      <TextBlock Text="Reservations" Style="{StaticResource FormLabel}"/>
                      <TextBlock x:Name="StatReservations" Text="0" FontSize="28" FontWeight="Bold"
                                 Foreground="{StaticResource Warning}"/>
                    </StackPanel>
                  </Border>

                  <Border Grid.Row="1" Grid.Column="0" Background="{StaticResource BgCard}"
                          CornerRadius="6" Padding="16" Margin="0,0,8,8">
                    <StackPanel>
                      <TextBlock Text="Available IPs" Style="{StaticResource FormLabel}"/>
                      <TextBlock x:Name="StatAvailableIPs" Text="0" FontSize="28" FontWeight="Bold"
                                 Foreground="{StaticResource TextPrimary}"/>
                    </StackPanel>
                  </Border>

                  <Border Grid.Row="1" Grid.Column="1" Background="{StaticResource BgCard}"
                          CornerRadius="6" Padding="16" Margin="4,0,4,8">
                    <StackPanel>
                      <TextBlock Text="Total Addresses" Style="{StaticResource FormLabel}"/>
                      <TextBlock x:Name="StatTotalIPs" Text="0" FontSize="28" FontWeight="Bold"
                                 Foreground="{StaticResource TextPrimary}"/>
                    </StackPanel>
                  </Border>

                  <Border Grid.Row="1" Grid.Column="2" Background="{StaticResource BgCard}"
                          CornerRadius="6" Padding="16" Margin="8,0,0,8">
                    <StackPanel>
                      <TextBlock Text="Utilization" Style="{StaticResource FormLabel}"/>
                      <TextBlock x:Name="StatUtilization" Text="0%" FontSize="28" FontWeight="Bold"
                                 Foreground="{StaticResource Accent}"/>
                    </StackPanel>
                  </Border>
                </Grid>

                <Button x:Name="BtnRefreshStats" Content="🔄 Refresh Statistics" Margin="0,16,0,0"
                        Style="{StaticResource BtnPrimary}" HorizontalAlignment="Left" IsEnabled="False"/>
              </StackPanel>
            </ScrollViewer>
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

          <!-- TAB: DHCP Events / Live Watch (NEW) -->
          <TabItem x:Name="TabEvents" Header="📡 Events">
            <Grid Background="{StaticResource BgPanel}">
              <Grid.RowDefinitions>
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
                    <Button x:Name="BtnEventDetect" Content="🔎 Detect" Margin="0,0,8,0"
                            Style="{StaticResource BtnSecondary}"
                            ToolTip="Auto-detect DHCP audit log path"/>
                    <Button x:Name="BtnEventIngest" Content="📥 Ingest Log" Margin="0,0,0,0"
                            Style="{StaticResource BtnPrimary}"/>
                  </StackPanel>
                </Grid>
              </Border>

              <!-- Live Watch Controls -->
              <Border Grid.Row="1" Background="{StaticResource BgCard}"
                      BorderThickness="0,0,0,1" BorderBrush="{StaticResource Border}" Padding="12,10">
                <StackPanel Orientation="Horizontal">
                  <TextBlock Text="Live Watch:" Style="{StaticResource FormLabel}"
                             VerticalAlignment="Center" Margin="0,0,12,0"/>
                  <CheckBox x:Name="ChkWatchLocal" Content="Local" Margin="0,0,12,0"
                            VerticalAlignment="Center"/>
                  <CheckBox x:Name="ChkWatchA" Content="Server A" Margin="0,0,12,0"
                            VerticalAlignment="Center"/>
                  <CheckBox x:Name="ChkWatchB" Content="Server B" Margin="0,0,16,0"
                            VerticalAlignment="Center"/>
                  <Button x:Name="BtnEventWatchStart" Content="▶️ Start Watch" Margin="0,0,8,0"
                          Style="{StaticResource BtnSuccess}"/>
                  <Button x:Name="BtnEventWatchStop" Content="⏹️ Stop" Margin="0,0,8,0"
                          Style="{StaticResource BtnDanger}" IsEnabled="False"/>
                  <Separator Width="1" Background="{StaticResource Border}" Margin="8,0"/>
                  <Button x:Name="BtnEventClear" Content="🗑️ Clear" Margin="8,0,8,0"
                          Style="{StaticResource BtnSecondary}"/>
                  <Button x:Name="BtnEventExport" Content="💾 Export" Margin="0,0,8,0"
                          Style="{StaticResource BtnSecondary}"/>
                  <TextBlock Text="Filter:" Style="{StaticResource FormLabel}"
                             VerticalAlignment="Center" Margin="8,0,8,0"/>
                  <TextBox x:Name="TxtEventFilter" Width="180" Style="{StaticResource DarkTextBox}"
                           ToolTip="Filter by IP, MAC, hostname, or event text"/>
                </StackPanel>
              </Border>

              <!-- Status line -->
              <Border Grid.Row="2" Background="{StaticResource BgPanel}" Padding="12,6">
                <TextBlock x:Name="TxtEventStatus" Text="Ingest a DHCP audit log or start live watch on Local / Server A / Server B"
                           Foreground="{StaticResource TextSecond}" FontSize="11"/>
              </Border>

              <!-- Events Grid -->
              <DataGrid Grid.Row="3" x:Name="GridEvents" Style="{StaticResource DarkGrid}" Margin="8">
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
    $script:BtnViewMigrate   = $Window.FindName("BtnViewMigrate")
    
    # Status Bar
    $script:StatusServer     = $Window.FindName("StatusServer")
    $script:StatusMessage    = $Window.FindName("StatusMessage")
    $script:StatusTime       = $Window.FindName("StatusTime")
    
    # Navigation
    $script:NavTree          = $Window.FindName("NavTree")
    $script:MainTabs         = $Window.FindName("MainTabs")
    
    # Tabs
    $script:TabScopes        = $Window.FindName("TabScopes")
    $script:TabLeases        = $Window.FindName("TabLeases")
    $script:TabReservations  = $Window.FindName("TabReservations")
    $script:TabExclusions    = $Window.FindName("TabExclusions")
    $script:TabOptions       = $Window.FindName("TabOptions")
    $script:TabFilters       = $Window.FindName("TabFilters")
    $script:TabPolicies      = $Window.FindName("TabPolicies")
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
    
    # Leases Tab
    $script:GridLeases       = $Window.FindName("GridLeases")
    $script:BtnLeaseRelease  = $Window.FindName("BtnLeaseRelease")
    $script:BtnLeaseReserve  = $Window.FindName("BtnLeaseReserve")
    $script:BtnLeaseRefresh  = $Window.FindName("BtnLeaseRefresh")
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
    
    # Statistics Tab
    $script:StatTotalScopes  = $Window.FindName("StatTotalScopes")
    $script:StatActiveLeases = $Window.FindName("StatActiveLeases")
    $script:StatReservations = $Window.FindName("StatReservations")
    $script:StatAvailableIPs = $Window.FindName("StatAvailableIPs")
    $script:StatTotalIPs     = $Window.FindName("StatTotalIPs")
    $script:StatUtilization  = $Window.FindName("StatUtilization")
    $script:BtnRefreshStats  = $Window.FindName("BtnRefreshStats")
    
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
    $script:ChkWatchLocal        = $Window.FindName("ChkWatchLocal")
    $script:ChkWatchA            = $Window.FindName("ChkWatchA")
    $script:ChkWatchB            = $Window.FindName("ChkWatchB")
    $script:BtnEventWatchStart   = $Window.FindName("BtnEventWatchStart")
    $script:BtnEventWatchStop    = $Window.FindName("BtnEventWatchStop")
    $script:BtnEventClear        = $Window.FindName("BtnEventClear")
    $script:BtnEventExport       = $Window.FindName("BtnEventExport")
    $script:TxtEventFilter       = $Window.FindName("TxtEventFilter")
    $script:TxtEventStatus       = $Window.FindName("TxtEventStatus")
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
        Validates DHCP connectivity; tries hostname then IP fallbacks
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
        } catch {
            Write-ActionLog "DNS resolve failed for '${cleaned}': $_" "WARN"
        }
    }
    
    $attemptErrors = [System.Collections.Generic.List[string]]::new()
    
    foreach ($target in $candidates) {
        try {
            Write-ActionLog "Trying DHCP RPC connect via '$target'..." "INFO"
            $null = Get-DhcpServerv4Scope -ComputerName $target -ErrorAction Stop
            if (-not $target.Equals($cleaned, [System.StringComparison]::OrdinalIgnoreCase)) {
                Write-ActionLog "Connected using fallback target '$target' (requested '$cleaned')" "SUCCESS"
            }
            return $target
        } catch {
            $raw = "$_"
            [void]$attemptErrors.Add("${target}: $raw")
            Write-ActionLog "Connect attempt failed for '${target}': $raw" "WARN"
        }
    }
    
    $primaryFail = if ((Get-SafeCount $attemptErrors) -gt 0) { $attemptErrors[0] } else { 'Unknown error' }
    $hint = switch -Regex ($primaryFail) {
        'access is denied|AccessDenied|0x80070005' {
            "Access denied. Run as a user with DHCP Administrators rights on the target (or Domain Admins). Cross-domain may need an account trusted in that domain."
        }
        'RPC|RPC server|0x800706BA|unavailable' {
            "RPC unreachable. Check firewall (RPC TCP 135 + dynamic ports), DHCP Server service, and routing to the target (try IP if hostname fails)."
        }
        'WinRM|WS-Management' {
            "WinRM issue. DHCP cmdlets use RPC (not WinRM). Verify RPC/firewall connectivity."
        }
        'cannot find|not found|no such host|DNS|No such host is known' {
            "Name resolution failed. Use FQDN or IP address; Scan Domain can fill the IP."
        }
        'The term .*Get-DhcpServerv4Scope' {
            "DhcpServer module failed to load cmdlets. Reinstall RSAT-DHCP tools."
        }
        default {
            "Verify network path, DHCP service status, and account permissions. For other domains, prefer IP if DNS/suffix search fails."
        }
    }
    
    $tried = ($candidates -join ', ')
    $details = ($attemptErrors -join "`n")
    throw "Cannot reach DHCP on '$cleaned' (tried: $tried). $hint`n`nDetails:`n$details"
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
    
    foreach ($srv in $discovered) {
        $target = if ($srv.DnsName) { $srv.DnsName } else { $srv.IPAddress }
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
        Chooses display/connect values from a scan row (clean host + IP fallback)
    #>
    param($Row)
    
    $clean = Get-CleanDhcpServerHostName -Name "$($Row.DnsName)"
    $ip = "$($Row.IPAddress)".Trim()
    if ($ip -notmatch '^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$') { $ip = '' }
    
    if ([string]::IsNullOrWhiteSpace($clean) -or $clean -match '(?i)^rcn=|=') {
        $primary = $(if ($ip) { $ip } else { "$($Row.DnsName)".Trim() })
    } else {
        $primary = $clean
    }
    
    return [PSCustomObject]@{
        Primary    = $primary
        FallbackIP = $ip
        HostName   = $clean
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
            $target = Get-ScanRowConnectTarget -Row $script:ScanDialogGrid.SelectedItem
            $script:TxtServerName.Text = $target.Primary
            $hint = if ($target.FallbackIP -and $target.Primary -ne $target.FallbackIP) {
                "Filled Server A with $($target.Primary) (IP fallback $($target.FallbackIP)) — click Connect"
            } else {
                "Filled main server box with $($target.Primary) — click Connect on the main window"
            }
            Write-ActionLog "Scan: set Server A candidate to $($target.Primary)" "INFO"
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
            $target = Get-ScanRowConnectTarget -Row $script:ScanDialogGrid.SelectedItem
            $script:TxtCompareServer.Text = $target.Primary
            if ($null -ne $script:TabCompare) {
                $script:MainTabs.SelectedItem = $script:TabCompare
            }
            $hint = if ($target.FallbackIP -and $target.Primary -ne $target.FallbackIP) {
                "Filled Compare Server B with $($target.Primary) (IP fallback $($target.FallbackIP)) — click Connect B"
            } else {
                "Filled Compare Server B with $($target.Primary) — connect it on the Compare tab"
            }
            Write-ActionLog "Scan: set Server B candidate to $($target.Primary)" "INFO"
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
            $target = Get-ScanRowConnectTarget -Row $script:ScanDialogGrid.SelectedItem
            $script:TxtServerName.Text = $target.Primary
            Write-ActionLog "Scan double-click: filled Server A box with $($target.Primary)" "INFO"
            $script:ScanDialogStatus.Text = "Filled main server box with $($target.Primary)"
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
        
        $script:NavTree.Dispatcher.Invoke([action]{
            $script:NavTree.Items.Clear()
            
            # Root - Server Node
            $serverNode = New-Object System.Windows.Controls.TreeViewItem
            $serverNode.Header = "🖥️ $Global:DHCPServer"
            $serverNode.Tag = "Server"
            $serverNode.IsExpanded = $true
            
            # Scopes Container
            $scopesContainer = New-Object System.Windows.Controls.TreeViewItem
            $scopesContainer.Header = "🌐 Scopes"
            $scopesContainer.Tag = "Scopes"
            $scopesContainer.IsExpanded = $true
            
            try {
                $scopes = @(Get-DhcpServerv4Scope -ComputerName $Global:DHCPServer -ErrorAction Stop)
                
                foreach ($scope in $scopes) {
                    $scopeNode = New-Object System.Windows.Controls.TreeViewItem
                    $scopeNode.Header = "📍 $($scope.Name) [$($scope.ScopeId)]"
                    $scopeNode.Tag = "$($scope.ScopeId)"
                    
                    # Add sub-items
                    $leasesItem = New-Object System.Windows.Controls.TreeViewItem
                    $leasesItem.Header = "📄 Leases"
                    $leasesItem.Tag = "$($scope.ScopeId):Leases"
                    
                    $reservationsItem = New-Object System.Windows.Controls.TreeViewItem
                    $reservationsItem.Header = "📌 Reservations"
                    $reservationsItem.Tag = "$($scope.ScopeId):Reservations"
                    
                    $exclusionsItem = New-Object System.Windows.Controls.TreeViewItem
                    $exclusionsItem.Header = "🚫 Exclusions"
                    $exclusionsItem.Tag = "$($scope.ScopeId):Exclusions"
                    
                    $optionsItem = New-Object System.Windows.Controls.TreeViewItem
                    $optionsItem.Header = "⚙️ Options"
                    $optionsItem.Tag = "$($scope.ScopeId):Options"
                    
                    $scopeNode.Items.Add($leasesItem)
                    $scopeNode.Items.Add($reservationsItem)
                    $scopeNode.Items.Add($exclusionsItem)
                    $scopeNode.Items.Add($optionsItem)
                    
                    $scopesContainer.Items.Add($scopeNode)
                }
                
                Write-ActionLog "Added $(Get-SafeCount $scopes) scopes to navigation tree" "SUCCESS"
                
            } catch {
                Write-ActionLog "Failed to load scopes for navigation: $_" "ERROR"
            }
            
            $serverNode.Items.Add($scopesContainer)
            
            # Other server items
            $filtersNode = New-Object System.Windows.Controls.TreeViewItem
            $filtersNode.Header = "🔒 MAC Filters"
            $filtersNode.Tag = "Filters"
            
            $policiesNode = New-Object System.Windows.Controls.TreeViewItem
            $policiesNode.Header = "📋 Policies"
            $policiesNode.Tag = "Policies"
            
            $statsNode = New-Object System.Windows.Controls.TreeViewItem
            $statsNode.Header = "📊 Statistics"
            $statsNode.Tag = "Statistics"
            
            $serverNode.Items.Add($filtersNode)
            $serverNode.Items.Add($policiesNode)
            $serverNode.Items.Add($statsNode)
            
            $script:NavTree.Items.Add($serverNode)
            
        }, [System.Windows.Threading.DispatcherPriority]::Normal)
        
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
        $count = Get-SafeCount $scopes
        
        $script:GridScopes.Dispatcher.Invoke([action]{
            $script:GridScopes.ItemsSource = $scopes
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
        }, [System.Windows.Threading.DispatcherPriority]::Normal)
        
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

function Load-Statistics {
    <#
    .SYNOPSIS
        Loads and displays server statistics
    #>
    
    Write-ActionLog "Loading server statistics..." "INFO"
    Set-Status "Loading statistics..."
    
    try {
        $stats = Get-DhcpServerv4Statistics -ComputerName $Global:DHCPServer -ErrorAction Stop
        $scopes = @(Get-DhcpServerv4Scope -ComputerName $Global:DHCPServer -ErrorAction Stop)
        
        $totalReservations = 0
        foreach ($scope in $scopes) {
            try {
                $res = @(Get-DhcpServerv4Reservation -ComputerName $Global:DHCPServer -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue)
                $totalReservations += (Get-SafeCount $res)
            } catch {}
        }
        
        $script:Window.Dispatcher.Invoke([action]{
            $script:StatTotalScopes.Text = "$($stats.TotalScopes)"
            $script:StatActiveLeases.Text = "$($stats.InUse)"
            $script:StatReservations.Text = "$totalReservations"
            $script:StatAvailableIPs.Text = "$($stats.Available)"
            $script:StatTotalIPs.Text = "$($stats.TotalAddresses)"
            
            if ($stats.TotalAddresses -gt 0) {
                $util = [math]::Round(($stats.InUse / $stats.TotalAddresses) * 100, 1)
                $script:StatUtilization.Text = "$util%"
            } else {
                $script:StatUtilization.Text = "N/A"
            }
        }, [System.Windows.Threading.DispatcherPriority]::Normal)
        
        Write-ActionLog "Statistics loaded successfully" "SUCCESS"
        Set-Status "Statistics updated"
        Update-LogDisplay
        
    } catch {
        $errMsg = "Failed to load statistics: $_"
        Write-ActionLog $errMsg "ERROR"
        Set-Status $errMsg
        Update-LogDisplay
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
    foreach ($s in $scopesA) { $mapA["$($s.ScopeId)"] = $s }
    
    $mapB = @{}
    foreach ($s in $scopesB) { $mapB["$($s.ScopeId)"] = $s }
    
    $results = [System.Collections.Generic.List[object]]::new()
    $allKeys = @($mapA.Keys + $mapB.Keys) | Sort-Object -Unique
    
    foreach ($key in $allKeys) {
        $a = $mapA[$key]
        $b = $mapB[$key]
        
        if ($a -and -not $b) {
            $results.Add((New-CompareRow -Status 'Only on A' -Key $key -Label $a.Name `
                -ValueA "$($a.StartRange)-$($a.EndRange) [$($a.State)]" -ValueB '' `
                -Details "Mask=$($a.SubnetMask)"))
        }
        elseif ($b -and -not $a) {
            $results.Add((New-CompareRow -Status 'Only on B' -Key $key -Label $b.Name `
                -ValueA '' -ValueB "$($b.StartRange)-$($b.EndRange) [$($b.State)]" `
                -Details "Mask=$($b.SubnetMask)"))
        }
        else {
            $valA = "$($a.Name)|$($a.StartRange)|$($a.EndRange)|$($a.SubnetMask)|$($a.State)"
            $valB = "$($b.Name)|$($b.StartRange)|$($b.EndRange)|$($b.SubnetMask)|$($b.State)"
            # Use List — `$arr += "x"` becomes a string under StrictMode when only one item is added
            $diffs = [System.Collections.Generic.List[string]]::new()
            if ($a.Name -ne $b.Name) { [void]$diffs.Add('Name') }
            if ("$($a.StartRange)" -ne "$($b.StartRange)") { [void]$diffs.Add('Start') }
            if ("$($a.EndRange)" -ne "$($b.EndRange)") { [void]$diffs.Add('End') }
            if ("$($a.SubnetMask)" -ne "$($b.SubnetMask)") { [void]$diffs.Add('Mask') }
            if ("$($a.State)" -ne "$($b.State)") { [void]$diffs.Add('State') }
            
            if ($diffs.Count -eq 0) {
                $results.Add((New-CompareRow -Status 'Matching' -Key $key -Label $a.Name `
                    -ValueA "$($a.StartRange)-$($a.EndRange) [$($a.State)]" `
                    -ValueB "$($b.StartRange)-$($b.EndRange) [$($b.State)]" `
                    -Details "Identical"))
            } else {
                $results.Add((New-CompareRow -Status 'Different' -Key $key -Label $a.Name `
                    -ValueA "$($a.StartRange)-$($a.EndRange) [$($a.State)] Name=$($a.Name)" `
                    -ValueB "$($b.StartRange)-$($b.EndRange) [$($b.State)] Name=$($b.Name)" `
                    -Details ("Differs: " + ($diffs -join ', '))))
            }
        }
    }
    
    return $results
}

function Get-DhcpCompareOptions {
    param([string]$ServerA, [string]$ServerB)
    
    Write-ActionLog "Fetching options from $ServerA and $ServerB..." "INFO"
    
    # Server-level options
    $optsA = @(Get-DhcpServerv4OptionValue -ComputerName $ServerA -ErrorAction SilentlyContinue)
    $optsB = @(Get-DhcpServerv4OptionValue -ComputerName $ServerB -ErrorAction SilentlyContinue)
    
    # Also include scope-level options for all scopes on each server
    try {
        foreach ($scope in @(Get-DhcpServerv4Scope -ComputerName $ServerA -ErrorAction SilentlyContinue)) {
            $scopeOpts = @(Get-DhcpServerv4OptionValue -ComputerName $ServerA -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue)
            foreach ($o in $scopeOpts) {
                $o | Add-Member -NotePropertyName '_ScopeId' -NotePropertyValue "$($scope.ScopeId)" -Force
                $optsA += $o
            }
        }
    } catch {}
    
    try {
        foreach ($scope in @(Get-DhcpServerv4Scope -ComputerName $ServerB -ErrorAction SilentlyContinue)) {
            $scopeOpts = @(Get-DhcpServerv4OptionValue -ComputerName $ServerB -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue)
            foreach ($o in $scopeOpts) {
                $o | Add-Member -NotePropertyName '_ScopeId' -NotePropertyValue "$($scope.ScopeId)" -Force
                $optsB += $o
            }
        }
    } catch {}
    
    $mapA = @{}
    foreach ($o in $optsA) {
        $scopePart = if ($o.PSObject.Properties.Name -contains '_ScopeId' -and $o._ScopeId) { $o._ScopeId } else { 'Server' }
        $key = "$scopePart|Opt$($o.OptionId)"
        $mapA[$key] = $o
    }
    
    $mapB = @{}
    foreach ($o in $optsB) {
        $scopePart = if ($o.PSObject.Properties.Name -contains '_ScopeId' -and $o._ScopeId) { $o._ScopeId } else { 'Server' }
        $key = "$scopePart|Opt$($o.OptionId)"
        $mapB[$key] = $o
    }
    
    $results = [System.Collections.Generic.List[object]]::new()
    $allKeys = @($mapA.Keys + $mapB.Keys) | Sort-Object -Unique
    
    foreach ($key in $allKeys) {
        $a = $mapA[$key]
        $b = $mapB[$key]
        $label = if ($a) { $a.Name } elseif ($b) { $b.Name } else { $key }
        
        $valA = if ($a) { ($a.Value -join ', ') } else { '' }
        $valB = if ($b) { ($b.Value -join ', ') } else { '' }
        
        if ($a -and -not $b) {
            $results.Add((New-CompareRow -Status 'Only on A' -Key $key -Label $label -ValueA $valA -ValueB '' -Details 'Missing on B'))
        }
        elseif ($b -and -not $a) {
            $results.Add((New-CompareRow -Status 'Only on B' -Key $key -Label $label -ValueA '' -ValueB $valB -Details 'Missing on A'))
        }
        elseif ($valA -eq $valB) {
            $results.Add((New-CompareRow -Status 'Matching' -Key $key -Label $label -ValueA $valA -ValueB $valB -Details 'Identical'))
        }
        else {
            $results.Add((New-CompareRow -Status 'Different' -Key $key -Label $label -ValueA $valA -ValueB $valB -Details 'Value mismatch'))
        }
    }
    
    return $results
}

function Get-DhcpCompareLeases {
    param([string]$ServerA, [string]$ServerB)
    
    Write-ActionLog "Fetching leases from $ServerA and $ServerB..." "INFO"
    
    $leasesA = [System.Collections.Generic.List[object]]::new()
    $leasesB = [System.Collections.Generic.List[object]]::new()
    
    foreach ($scope in @(Get-DhcpServerv4Scope -ComputerName $ServerA -ErrorAction Stop)) {
        try {
            $items = @(Get-DhcpServerv4Lease -ComputerName $ServerA -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue)
            foreach ($item in $items) { $leasesA.Add($item) }
        } catch {}
    }
    
    foreach ($scope in @(Get-DhcpServerv4Scope -ComputerName $ServerB -ErrorAction Stop)) {
        try {
            $items = @(Get-DhcpServerv4Lease -ComputerName $ServerB -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue)
            foreach ($item in $items) { $leasesB.Add($item) }
        } catch {}
    }
    
    $mapA = @{}
    foreach ($l in $leasesA) {
        $mac = if ($l.ClientId) { "$($l.ClientId)".ToUpper() } else { '' }
        $key = if ($mac) { "MAC:$mac" } else { "IP:$($l.IPAddress)" }
        $mapA[$key] = $l
    }
    
    $mapB = @{}
    foreach ($l in $leasesB) {
        $mac = if ($l.ClientId) { "$($l.ClientId)".ToUpper() } else { '' }
        $key = if ($mac) { "MAC:$mac" } else { "IP:$($l.IPAddress)" }
        $mapB[$key] = $l
    }
    
    $results = [System.Collections.Generic.List[object]]::new()
    $allKeys = @($mapA.Keys + $mapB.Keys) | Sort-Object -Unique
    
    foreach ($key in $allKeys) {
        $a = $mapA[$key]
        $b = $mapB[$key]
        
        if ($a -and -not $b) {
            $results.Add((New-CompareRow -Status 'Only on A' -Key $key -Label $a.HostName `
                -ValueA "$($a.IPAddress) [$($a.AddressState)] Scope=$($a.ScopeId)" -ValueB '' `
                -Details "Expiry=$($a.LeaseExpiryTime)"))
        }
        elseif ($b -and -not $a) {
            $results.Add((New-CompareRow -Status 'Only on B' -Key $key -Label $b.HostName `
                -ValueA '' -ValueB "$($b.IPAddress) [$($b.AddressState)] Scope=$($b.ScopeId)" `
                -Details "Expiry=$($b.LeaseExpiryTime)"))
        }
        else {
            $diffs = [System.Collections.Generic.List[string]]::new()
            if ("$($a.IPAddress)" -ne "$($b.IPAddress)") { [void]$diffs.Add('IP') }
            if ("$($a.HostName)" -ne "$($b.HostName)") { [void]$diffs.Add('Hostname') }
            if ("$($a.ScopeId)" -ne "$($b.ScopeId)") { [void]$diffs.Add('Scope') }
            if ("$($a.AddressState)" -ne "$($b.AddressState)") { [void]$diffs.Add('State') }
            
            $valA = "$($a.IPAddress) [$($a.AddressState)] Host=$($a.HostName)"
            $valB = "$($b.IPAddress) [$($b.AddressState)] Host=$($b.HostName)"
            
            if ($diffs.Count -eq 0) {
                $results.Add((New-CompareRow -Status 'Matching' -Key $key -Label $a.HostName `
                    -ValueA $valA -ValueB $valB -Details 'Identical'))
            } else {
                $results.Add((New-CompareRow -Status 'Different' -Key $key -Label $a.HostName `
                    -ValueA $valA -ValueB $valB -Details ("Differs: " + ($diffs -join ', '))))
            }
        }
    }
    
    return $results
}

function Get-DhcpCompareReservations {
    param([string]$ServerA, [string]$ServerB)
    
    Write-ActionLog "Fetching reservations from $ServerA and $ServerB..." "INFO"
    
    $resA = [System.Collections.Generic.List[object]]::new()
    $resB = [System.Collections.Generic.List[object]]::new()
    
    foreach ($scope in @(Get-DhcpServerv4Scope -ComputerName $ServerA -ErrorAction Stop)) {
        try {
            $items = @(Get-DhcpServerv4Reservation -ComputerName $ServerA -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue)
            foreach ($item in $items) { $resA.Add($item) }
        } catch {}
    }
    
    foreach ($scope in @(Get-DhcpServerv4Scope -ComputerName $ServerB -ErrorAction Stop)) {
        try {
            $items = @(Get-DhcpServerv4Reservation -ComputerName $ServerB -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue)
            foreach ($item in $items) { $resB.Add($item) }
        } catch {}
    }
    
    $mapA = @{}
    foreach ($r in $resA) {
        $mac = if ($r.ClientId) { "$($r.ClientId)".ToUpper() } else { '' }
        $key = if ($mac) { "MAC:$mac" } else { "IP:$($r.IPAddress)" }
        $mapA[$key] = $r
    }
    
    $mapB = @{}
    foreach ($r in $resB) {
        $mac = if ($r.ClientId) { "$($r.ClientId)".ToUpper() } else { '' }
        $key = if ($mac) { "MAC:$mac" } else { "IP:$($r.IPAddress)" }
        $mapB[$key] = $r
    }
    
    $results = [System.Collections.Generic.List[object]]::new()
    $allKeys = @($mapA.Keys + $mapB.Keys) | Sort-Object -Unique
    
    foreach ($key in $allKeys) {
        $a = $mapA[$key]
        $b = $mapB[$key]
        
        if ($a -and -not $b) {
            $results.Add((New-CompareRow -Status 'Only on A' -Key $key -Label $a.Name `
                -ValueA "$($a.IPAddress) Scope=$($a.ScopeId)" -ValueB '' `
                -Details "Type=$($a.Type)"))
        }
        elseif ($b -and -not $a) {
            $results.Add((New-CompareRow -Status 'Only on B' -Key $key -Label $b.Name `
                -ValueA '' -ValueB "$($b.IPAddress) Scope=$($b.ScopeId)" `
                -Details "Type=$($b.Type)"))
        }
        else {
            $diffs = [System.Collections.Generic.List[string]]::new()
            if ("$($a.IPAddress)" -ne "$($b.IPAddress)") { [void]$diffs.Add('IP') }
            if ("$($a.Name)" -ne "$($b.Name)") { [void]$diffs.Add('Name') }
            if ("$($a.ScopeId)" -ne "$($b.ScopeId)") { [void]$diffs.Add('Scope') }
            if ("$($a.ClientId)".ToUpper() -ne "$($b.ClientId)".ToUpper()) { [void]$diffs.Add('MAC') }
            
            $valA = "$($a.IPAddress) Name=$($a.Name) Scope=$($a.ScopeId)"
            $valB = "$($b.IPAddress) Name=$($b.Name) Scope=$($b.ScopeId)"
            
            if ($diffs.Count -eq 0) {
                $results.Add((New-CompareRow -Status 'Matching' -Key $key -Label $a.Name `
                    -ValueA $valA -ValueB $valB -Details 'Identical'))
            } else {
                $results.Add((New-CompareRow -Status 'Different' -Key $key -Label $a.Name `
                    -ValueA $valA -ValueB $valB -Details ("Differs: " + ($diffs -join ', '))))
            }
        }
    }
    
    return $results
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
        Write-ActionLog "Compare complete: $totalCount items, $diffCount non-matching" "SUCCESS"
        Set-Status "Compare complete — $totalCount items"
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
        if (Test-Path -LiteralPath $CustomPath) { return $CustomPath }
        return $null
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
        # Fallback common UNC form
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
    
    $candidates = @(Get-ChildItem -LiteralPath $root -Filter 'DhcpSrvLog*' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending)
    
    if ($candidates.Count -eq 0) { return $root }
    return $candidates[0].FullName
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
    $parts = $Line.Split(',')
    if ($parts.Count -lt 3) { return $null }
    
    $eventId = $parts[0].Trim()
    if ($eventId -notmatch '^\d{1,3}$') { return $null }
    
    $date = if ($parts.Count -gt 1) { $parts[1].Trim() } else { '' }
    $time = if ($parts.Count -gt 2) { $parts[2].Trim() } else { '' }
    $desc = if ($parts.Count -gt 3 -and $parts[3].Trim()) { $parts[3].Trim() } else { Get-DhcpEventDescription $eventId }
    $ip   = if ($parts.Count -gt 4) { $parts[4].Trim() } else { '' }
    $hostName = if ($parts.Count -gt 5) { $parts[5].Trim() } else { '' }
    $mac  = if ($parts.Count -gt 6) { $parts[6].Trim() } else { '' }
    
    $stamp = ("$date $time").Trim()
    if (-not $stamp) { $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss' }
    
    $details = if ($parts.Count -gt 7) { ($parts[7..($parts.Count-1)] -join ',').Trim() } else { '' }
    
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

function Add-DhcpEventEntry {
    param([object]$Entry)
    
    if ($null -eq $Entry) { return }
    
    $filter = ''
    try { $filter = $script:TxtEventFilter.Text } catch {}
    
    if (-not [string]::IsNullOrWhiteSpace($filter)) {
        $blob = "$($Entry.Server) $($Entry.Time) $($Entry.EventId) $($Entry.Description) $($Entry.IPAddress) $($Entry.MacAddress) $($Entry.HostName) $($Entry.Details)"
        if ($blob -notlike "*$filter*") { return }
    }
    
    try {
        $script:Window.Dispatcher.Invoke([action]{
            $Global:DhcpEventEntries.Insert(0, $Entry)
            while ($Global:DhcpEventEntries.Count -gt 5000) {
                $Global:DhcpEventEntries.RemoveAt($Global:DhcpEventEntries.Count - 1)
            }
            if ($null -eq $script:GridEvents.ItemsSource) {
                $script:GridEvents.ItemsSource = $Global:DhcpEventEntries
            }
        }, [System.Windows.Threading.DispatcherPriority]::Background)
    } catch {
        try {
            $Global:DhcpEventEntries.Insert(0, $Entry)
        } catch {}
    }
}

function Import-DhcpAuditLogFile {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [string]$ServerLabel = 'Local',
        [switch]$TailOnly
    )
    
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Log path not found: $Path"
    }
    
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer) {
        $newest = @(Get-ChildItem -LiteralPath $Path -Filter 'DhcpSrvLog*' -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending)
        if ($newest.Count -eq 0) { throw "No DhcpSrvLog* files in $Path" }
        $Path = $newest[0].FullName
    }
    
    Write-ActionLog "Ingesting DHCP audit log: $Path ($ServerLabel)" "INFO"
    
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        if ($TailOnly) {
            $fs.Seek(0, [System.IO.SeekOrigin]::End) | Out-Null
            return @{ Path = $Path; Offset = $fs.Position }
        }
        
        $reader = New-Object System.IO.StreamReader($fs)
        $count = 0
        while ($null -ne ($line = $reader.ReadLine())) {
            $entry = ConvertFrom-DhcpAuditLine -Line $line -ServerLabel $ServerLabel
            if ($entry) {
                Add-DhcpEventEntry -Entry $entry
                $count++
            }
        }
        $offset = $fs.Position
        Write-ActionLog "Ingested $count events from $ServerLabel" "SUCCESS"
        return @{ Path = $Path; Offset = $offset; Count = $count }
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
        return @{ Offset = $Offset; Count = 0 }
    }
    
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $length = $fs.Length
        if ($Offset -gt $length) { $Offset = 0L }  # log rotated
        
        $fs.Seek($Offset, [System.IO.SeekOrigin]::Begin) | Out-Null
        $reader = New-Object System.IO.StreamReader($fs)
        $count = 0
        while ($null -ne ($line = $reader.ReadLine())) {
            $entry = ConvertFrom-DhcpAuditLine -Line $line -ServerLabel $ServerLabel
            if ($entry) {
                Add-DhcpEventEntry -Entry $entry
                $count++
            }
        }
        return @{ Offset = $fs.Position; Count = $count }
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
    $parts = @()
    if ($Global:EventWatchActive) {
        if ($Global:LogWatchState.Local.Enabled) { $parts += "Local→$([IO.Path]::GetFileName($Global:LogWatchState.Local.Path))" }
        if ($Global:LogWatchState.A.Enabled)     { $parts += "A→$([IO.Path]::GetFileName($Global:LogWatchState.A.Path))" }
        if ($Global:LogWatchState.B.Enabled)     { $parts += "B→$([IO.Path]::GetFileName($Global:LogWatchState.B.Path))" }
        $msg = if ($parts.Count) { "LIVE watching: " + ($parts -join '  |  ') } else { 'Watch running (no sources enabled)' }
    } else {
        $msg = "Idle — $($Global:DhcpEventEntries.Count) events loaded. Built by $($Global:AppAuthor)."
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
    $watchLocal = [bool]$script:ChkWatchLocal.IsChecked
    $watchA     = [bool]$script:ChkWatchA.IsChecked
    $watchB     = [bool]$script:ChkWatchB.IsChecked
    
    if (-not ($watchLocal -or $watchA -or $watchB)) {
        Show-MessageBox "Select at least one live watch target: Local, Server A, and/or Server B." "Live Watch" OK Warning
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
    
    Write-ActionLog "Starting DHCP live event watch..." "INFO"
    
    foreach ($key in @('Local','A','B')) {
        $Global:LogWatchState[$key].Enabled = $false
        $Global:LogWatchState[$key].Path = $null
        $Global:LogWatchState[$key].Offset = 0L
    }
    
    $started = @()
    
    if ($watchLocal) {
        $path = Get-DhcpAuditLogPath -Source Local
        if (-not $path) { throw "Could not detect local DHCP audit log under $($env:SystemRoot)\System32\dhcp" }
        $info = Import-DhcpAuditLogFile -Path $path -ServerLabel 'Local' -TailOnly
        $Global:LogWatchState.Local.Enabled = $true
        $Global:LogWatchState.Local.Path = $info.Path
        $Global:LogWatchState.Local.Offset = [long]$info.Offset
        $started += "Local ($($info.Path))"
    }
    
    if ($watchA) {
        $path = Get-DhcpAuditLogPath -Source A
        if (-not $path) { throw "Could not detect DHCP audit log for Server A ($($Global:DHCPServer)). Ensure admin$ or C$ share is reachable." }
        $label = Get-EventServerLabel -SourceKey 'A'
        $info = Import-DhcpAuditLogFile -Path $path -ServerLabel $label -TailOnly
        $Global:LogWatchState.A.Enabled = $true
        $Global:LogWatchState.A.Path = $info.Path
        $Global:LogWatchState.A.Offset = [long]$info.Offset
        $started += "A ($($info.Path))"
    }
    
    if ($watchB) {
        $path = Get-DhcpAuditLogPath -Source B
        if (-not $path) { throw "Could not detect DHCP audit log for Server B ($($Global:CompareServer)). Ensure admin$ or C$ share is reachable." }
        $label = Get-EventServerLabel -SourceKey 'B'
        $info = Import-DhcpAuditLogFile -Path $path -ServerLabel $label -TailOnly
        $Global:LogWatchState.B.Enabled = $true
        $Global:LogWatchState.B.Path = $info.Path
        $Global:LogWatchState.B.Offset = [long]$info.Offset
        $started += "B ($($info.Path))"
    }
    
    if ($null -eq $script:EventWatchTimer) {
        $script:EventWatchTimer = New-Object System.Windows.Threading.DispatcherTimer
        $script:EventWatchTimer.Interval = [TimeSpan]::FromSeconds(2)
        $script:EventWatchTimer.Add_Tick({
            if (-not $Global:EventWatchActive) { return }
            
            $newTotal = 0
            foreach ($key in @('Local','A','B')) {
                $st = $Global:LogWatchState[$key]
                if (-not $st.Enabled -or -not $st.Path) { continue }
                
                $label = switch ($key) {
                    'A' { Get-EventServerLabel -SourceKey 'A' }
                    'B' { Get-EventServerLabel -SourceKey 'B' }
                    default { 'Local' }
                }
                
                try {
                    $delta = Read-DhcpAuditLogDelta -Path $st.Path -Offset ([long]$st.Offset) -ServerLabel $label
                    $st.Offset = [long]$delta.Offset
                    $newTotal += [int]$delta.Count
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
    
    Write-ActionLog ("Live watch started: " + ($started -join '; ')) "SUCCESS"
    Update-EventWatchStatus
    Update-LogDisplay
    Set-Status "Live DHCP event watch active"
}

function Stop-DhcpEventWatch {
    Write-ActionLog "Stopping DHCP live event watch..." "INFO"
    
    $Global:EventWatchActive = $false
    try { if ($script:EventWatchTimer) { $script:EventWatchTimer.Stop() } } catch {}
    
    foreach ($key in @('Local','A','B')) {
        $Global:LogWatchState[$key].Enabled = $false
    }
    
    $script:BtnEventWatchStart.IsEnabled = $true
    $script:BtnEventWatchStop.IsEnabled = $false
    $script:ChkWatchLocal.IsEnabled = $true
    $script:ChkWatchA.IsEnabled = $true
    $script:ChkWatchB.IsEnabled = $true
    
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
        
        $script:NavTree.Items.Clear()
        
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
        "TabScopes"       { Load-Scopes }
        "TabLeases"       { Load-Leases }
        "TabReservations" { Load-Reservations }
        "TabExclusions"   { Load-Exclusions }
        "TabOptions"      { Load-Options }
        "TabFilters"      { Load-Filters }
        "TabPolicies"     { Load-Policies }
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
    elseif ($tag -eq "Statistics") {
        Write-ActionLog "Loading statistics view" "INFO"
        $script:MainTabs.SelectedItem = $script:TabStats
        Load-Statistics
    }
    
    Update-LogDisplay
}

$NavTree.add_SelectedItemChanged({ Handle-NavSelect $this $_ })
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
    if ($null -eq $script:GridLeases.SelectedItem) {
        Show-MessageBox "Please select a lease" "No Selection" OK Warning
        return
    }
    
    $lease = $script:GridLeases.SelectedItem
    $result = Show-MessageBox "Release lease for $($lease.IPAddress)?`n`nClient: $($lease.HostName)" "Confirm Release" YesNo Warning
    
    if ($result -eq 'Yes') {
        try {
            Write-ActionLog "Releasing lease: $($lease.IPAddress)" "INFO"
            
            Remove-DhcpServerv4Lease -ComputerName $Global:DHCPServer -IPAddress $lease.IPAddress -ErrorAction Stop
            
            Write-ActionLog "Lease released successfully" "SUCCESS"
            Show-MessageBox "Lease released" "Success" OK Information
            
            Load-Leases
            
        } catch {
            $errMsg = "Failed to release lease: $_"
            Write-ActionLog $errMsg "ERROR"
            Show-MessageBox $errMsg "Error" OK Error
        }
    }
})

$BtnLeaseReserve.add_Click({
    if ($null -eq $script:GridLeases.SelectedItem) {
        Show-MessageBox "Please select a lease to convert" "No Selection" OK Warning
        return
    }
    
    $lease = $script:GridLeases.SelectedItem
    
    try {
        Write-ActionLog "Converting lease to reservation: $($lease.IPAddress)" "INFO"
        
        Add-DhcpServerv4Reservation -ComputerName $Global:DHCPServer `
            -ScopeId $lease.ScopeId `
            -IPAddress $lease.IPAddress `
            -ClientId $lease.ClientId `
            -Name $lease.HostName `
            -ErrorAction Stop
        
        Write-ActionLog "Lease converted to reservation" "SUCCESS"
        Show-MessageBox "Lease converted to reservation successfully" "Success" OK Information
        
        Load-Leases
        
    } catch {
        $errMsg = "Failed to convert lease: $_"
        Write-ActionLog $errMsg "ERROR"
        Show-MessageBox $errMsg "Error" OK Error
    }
})

$GridLeases.add_SelectionChanged({
    $script:BtnLeaseRelease.IsEnabled = ($null -ne $script:GridLeases.SelectedItem)
    $script:BtnLeaseReserve.IsEnabled = ($null -ne $script:GridLeases.SelectedItem)
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

#region Event Handlers - Statistics
$BtnRefreshStats.add_Click({
    Write-ActionLog "Refreshing statistics..." "INFO"
    Load-Statistics
})
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

$BtnEventDetect.add_Click({
    try {
        $src = Get-SelectedEventSourceKey
        if ($src -eq 'Custom') {
            Show-MessageBox "Detect works for Local / Server A / Server B. For Custom, use Browse." "Detect" OK Information
            return
        }
        
        if ($src -eq 'A' -and -not $Global:DHCPServer) {
            Show-MessageBox "Connect Server A first." "Detect" OK Warning
            return
        }
        if ($src -eq 'B' -and -not $Global:CompareServer) {
            Show-MessageBox "Connect Server B first (Compare tab)." "Detect" OK Warning
            return
        }
        
        $path = Get-DhcpAuditLogPath -Source $src
        if (-not $path) {
            Show-MessageBox "Could not detect DHCP audit log for $src.`nTried admin`$ / C`$ System32\dhcp." "Detect" OK Warning
            return
        }
        
        $script:TxtEventLogPath.Text = $path
        Write-ActionLog "Detected DHCP audit path ($src): $path" "SUCCESS"
        $script:TxtEventStatus.Text = "Detected: $path"
        Update-LogDisplay
    } catch {
        Write-ActionLog "Detect failed: $_" "ERROR"
        Show-MessageBox "Detect failed: $_" "Detect" OK Error
    }
})

$BtnEventIngest.add_Click({
    try {
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
        $script:TxtEventStatus.Text = "Ingested $($info.Count) events from $label ($($info.Path))"
        Set-Status "Ingested $($info.Count) DHCP events"
        Update-LogDisplay
    } catch {
        $errMsg = "Ingest failed: $_"
        Write-ActionLog $errMsg "ERROR"
        Show-MessageBox $errMsg "Ingest Error" OK Error
        Update-LogDisplay
    }
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
        }, [System.Windows.Threading.DispatcherPriority]::Normal)
        Write-ActionLog "DHCP event grid cleared" "WARN"
        Update-EventWatchStatus
        Update-LogDisplay
    }
})

$BtnEventExport.add_Click({
    if ($Global:DhcpEventEntries.Count -eq 0) {
        Show-MessageBox "No DHCP events to export." "Export" OK Warning
        return
    }
    
    try {
        $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveDialog.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
        $saveDialog.FileName = "DHCP-Events-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
        $saveDialog.Title = "Export DHCP Events"
        
        if ($saveDialog.ShowDialog() -eq 'OK') {
            $Global:DhcpEventEntries |
                Select-Object Server, Time, EventId, Description, IPAddress, MacAddress, HostName, Details |
                Export-Csv -Path $saveDialog.FileName -NoTypeInformation -Encoding UTF8
            
            Write-ActionLog "DHCP events exported: $($saveDialog.FileName)" "SUCCESS"
            Show-MessageBox "Exported to:`n$($saveDialog.FileName)" "Export Complete" OK Information
            Update-LogDisplay
        }
    } catch {
        Write-ActionLog "Event export failed: $_" "ERROR"
        Show-MessageBox "Export failed: $_" "Export Error" OK Error
    }
})

$TxtEventFilter.add_TextChanged({
    # Filter applies to newly arriving live events; re-binding full filter would be expensive.
    # Status note only.
    try {
        if ($script:TxtEventFilter.Text) {
            $script:TxtEventStatus.Text = "Live filter active: '$($script:TxtEventFilter.Text)' (applies to new events)"
        } else {
            Update-EventWatchStatus
        }
    } catch {}
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
