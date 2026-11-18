#Requires -Version 5.1
<#
.SYNOPSIS
    Modern WPF GUI for validating Group Policy Preference (GPP) drive mappings.

.DESCRIPTION
    Provides a feature-rich graphical interface for testing GPO drive mappings
    against Active Directory users, with real-time validation, conflict detection,
    and comprehensive reporting capabilities.

.NOTES
    Version: 1.0
    Requires: PowerShell 5.1+, .NET Framework 4.5+, ActiveDirectory and GroupPolicy modules
    
    Note: This GUI requires a desktop environment with WPF support. On Windows Server,
    you may need to use the CLI version (Test-GpoDriveMapTargeting.ps1) if:
    - Running Server Core without Desktop Experience
    - Connected via remote PowerShell (no GUI forwarding)
    - WPF assemblies are not available
#>

# ---------------------------------------------------------------------------
# Pre-flight checks and error handling
# ---------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'

Write-Host "GPO Drive Mapping Validator - GUI Launcher" -ForegroundColor Cyan
Write-Host "Loading components..." -ForegroundColor Gray

# Check if running on Server
$osInfo = try { Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue } catch { $null }
if ($osInfo -and $osInfo.Caption -like "*Server*") {
    Write-Host ""
    Write-Host "⚠ WARNING: Windows Server Detected" -ForegroundColor Yellow
    Write-Host "  OS: $($osInfo.Caption)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "The GUI may not work properly on Server environments without full GUI support." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "If this hangs or fails, press Ctrl+C and use the CLI version:" -ForegroundColor Cyan
    Write-Host "  .\Test-GpoDriveMapTargeting.ps1 -GpoName `"Your GPO`" -TargetUsers alice,bob" -ForegroundColor White
    Write-Host ""
    Write-Host "Or use the interactive launcher:" -ForegroundColor Cyan
    Write-Host "  .\Start-GPOValidator.ps1" -ForegroundColor White
    Write-Host ""
    Start-Sleep -Seconds 3
}

# Try to load WPF assemblies with error handling
try {
    Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
    Add-Type -AssemblyName PresentationCore -ErrorAction Stop
    Add-Type -AssemblyName WindowsBase -ErrorAction Stop
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    Write-Host "✓ WPF assemblies loaded successfully" -ForegroundColor Green
}
catch {
    Write-Host ""
    Write-Host "✗ ERROR: Failed to load WPF assemblies" -ForegroundColor Red
    Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "This system cannot run the GUI. Possible reasons:" -ForegroundColor Yellow
    Write-Host "  • Windows Server Core (no Desktop Experience)" -ForegroundColor Yellow
    Write-Host "  • Missing .NET Framework WPF components" -ForegroundColor Yellow
    Write-Host "  • Remote PowerShell session" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "SOLUTION: Use the CLI version instead:" -ForegroundColor Cyan
    Write-Host "  .\Test-GpoDriveMapTargeting.ps1 -GpoName `"Your GPO`" -TargetUsers alice,bob" -ForegroundColor White
    Write-Host ""
    Write-Host "See EXAMPLES.md for CLI usage examples." -ForegroundColor Cyan
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

$script:ValidationResults = $null
$script:BackendScriptPath = Join-Path $PSScriptRoot "Test-GpoDriveMapTargeting.ps1"

# ---------------------------------------------------------------------------
# XAML Definition
# ---------------------------------------------------------------------------
[xml]$xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="GPO Drive Mapping Validator" 
    Height="850" 
    Width="1400"
    WindowStartupLocation="CenterScreen"
    Background="#F5F5F5">
    
    <Window.Resources>
        <!-- Modern Color Scheme -->
        <SolidColorBrush x:Key="PrimaryBrush" Color="#0078D4"/>
        <SolidColorBrush x:Key="SecondaryBrush" Color="#106EBE"/>
        <SolidColorBrush x:Key="AccentBrush" Color="#00BCF2"/>
        <SolidColorBrush x:Key="SuccessBrush" Color="#107C10"/>
        <SolidColorBrush x:Key="WarningBrush" Color="#FF8C00"/>
        <SolidColorBrush x:Key="ErrorBrush" Color="#E81123"/>
        <SolidColorBrush x:Key="BorderBrush" Color="#CCCCCC"/>
        
        <!-- Button Style -->
        <Style x:Key="ModernButton" TargetType="Button">
            <Setter Property="Background" Value="{StaticResource PrimaryBrush}"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="15,8"/>
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}" 
                                CornerRadius="4" 
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="{StaticResource SecondaryBrush}"/>
                </Trigger>
                <Trigger Property="IsEnabled" Value="False">
                    <Setter Property="Background" Value="#CCCCCC"/>
                    <Setter Property="Foreground" Value="#666666"/>
                </Trigger>
            </Style.Triggers>
        </Style>
        
        <!-- TextBox Style -->
        <Style x:Key="ModernTextBox" TargetType="TextBox">
            <Setter Property="Padding" Value="8"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="BorderBrush" Value="{StaticResource BorderBrush}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Background" Value="White"/>
        </Style>
        
        <!-- ComboBox Style -->
        <Style x:Key="ModernComboBox" TargetType="ComboBox">
            <Setter Property="Padding" Value="8"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="BorderBrush" Value="{StaticResource BorderBrush}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Background" Value="White"/>
        </Style>
        
        <!-- GroupBox Style -->
        <Style x:Key="ModernGroupBox" TargetType="GroupBox">
            <Setter Property="BorderBrush" Value="{StaticResource BorderBrush}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="10"/>
            <Setter Property="Margin" Value="5"/>
            <Setter Property="Background" Value="White"/>
        </Style>
        
        <!-- DataGrid Style -->
        <Style x:Key="ModernDataGrid" TargetType="DataGrid">
            <Setter Property="AutoGenerateColumns" Value="False"/>
            <Setter Property="IsReadOnly" Value="True"/>
            <Setter Property="CanUserAddRows" Value="False"/>
            <Setter Property="CanUserDeleteRows" Value="False"/>
            <Setter Property="SelectionMode" Value="Single"/>
            <Setter Property="GridLinesVisibility" Value="Horizontal"/>
            <Setter Property="HeadersVisibility" Value="Column"/>
            <Setter Property="AlternatingRowBackground" Value="#F9F9F9"/>
            <Setter Property="RowBackground" Value="White"/>
            <Setter Property="BorderBrush" Value="{StaticResource BorderBrush}"/>
            <Setter Property="BorderThickness" Value="1"/>
        </Style>
    </Window.Resources>
    
    <Grid Margin="10">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        
        <!-- Header -->
        <Border Grid.Row="0" Background="{StaticResource PrimaryBrush}" CornerRadius="6" Padding="15" Margin="0,0,0,10">
            <StackPanel>
                <TextBlock Text="GPO Drive Mapping Validator" FontSize="24" FontWeight="Bold" Foreground="White"/>
                <TextBlock Text="Validate Item-Level Targeting filters before GPO deployment" FontSize="12" Foreground="#E0E0E0" Margin="0,5,0,0"/>
            </StackPanel>
        </Border>
        
        <!-- Main Content -->
        <TabControl Grid.Row="1" Background="Transparent" BorderThickness="0">
            <!-- Configuration Tab -->
            <TabItem Header="Configuration" FontSize="14" FontWeight="SemiBold">
                <ScrollViewer VerticalScrollBarVisibility="Auto">
                    <StackPanel Margin="10">
                        <!-- GPO Selection -->
                        <GroupBox Header="GPO Selection" Style="{StaticResource ModernGroupBox}">
                            <Grid>
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="Auto"/>
                                </Grid.RowDefinitions>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="150"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>
                                
                                <TextBlock Grid.Row="0" Grid.Column="0" Text="Domain:" VerticalAlignment="Center" Margin="5"/>
                                <TextBox Grid.Row="0" Grid.Column="1" Name="txtDomain" Style="{StaticResource ModernTextBox}" Margin="5"/>
                                <Button Grid.Row="0" Grid.Column="2" Name="btnDetectDomain" Content="Auto-Detect" Style="{StaticResource ModernButton}" Margin="5" Width="120"/>
                                
                                <TextBlock Grid.Row="1" Grid.Column="0" Text="GPO Name:" VerticalAlignment="Center" Margin="5"/>
                                <TextBox Grid.Row="1" Grid.Column="1" Name="txtGpoName" Style="{StaticResource ModernTextBox}" Margin="5"/>
                                <Button Grid.Row="1" Grid.Column="2" Name="btnBrowseGpo" Content="Browse GPOs" Style="{StaticResource ModernButton}" Margin="5" Width="120"/>
                                
                                <TextBlock Grid.Row="2" Grid.Column="0" Text="Or Drives.xml Path:" VerticalAlignment="Center" Margin="5"/>
                                <TextBox Grid.Row="2" Grid.Column="1" Name="txtXmlPath" Style="{StaticResource ModernTextBox}" Margin="5"/>
                                <Button Grid.Row="2" Grid.Column="2" Name="btnBrowseXml" Content="Browse..." Style="{StaticResource ModernButton}" Margin="5" Width="120"/>
                            </Grid>
                        </GroupBox>
                        
                        <!-- Test Subjects -->
                        <GroupBox Header="Test Subjects" Style="{StaticResource ModernGroupBox}">
                            <Grid>
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="Auto"/>
                                </Grid.RowDefinitions>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="150"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>
                                
                                <RadioButton Grid.Row="0" Grid.Column="0" Name="rbTargetUsers" Content="Specific Users:" VerticalAlignment="Center" Margin="5" GroupName="TargetType" IsChecked="True"/>
                                <TextBox Grid.Row="0" Grid.Column="1" Name="txtTargetUsers" Style="{StaticResource ModernTextBox}" Margin="5" ToolTip="Enter usernames separated by commas"/>
                                <Button Grid.Row="0" Grid.Column="2" Name="btnBrowseUsers" Content="Browse AD" Style="{StaticResource ModernButton}" Margin="5" Width="120"/>
                                
                                <RadioButton Grid.Row="1" Grid.Column="0" Name="rbTargetOU" Content="All Users in OU:" VerticalAlignment="Center" Margin="5" GroupName="TargetType"/>
                                <TextBox Grid.Row="1" Grid.Column="1" Name="txtTargetOU" Style="{StaticResource ModernTextBox}" Margin="5" IsEnabled="False" ToolTip="Enter OU Distinguished Name"/>
                                <Button Grid.Row="1" Grid.Column="2" Name="btnBrowseOU" Content="Browse AD" Style="{StaticResource ModernButton}" Margin="5" Width="120" IsEnabled="False"/>
                                
                                <RadioButton Grid.Row="2" Grid.Column="0" Name="rbSimulated" Content="Simulated Users:" VerticalAlignment="Center" Margin="5" GroupName="TargetType"/>
                                <TextBlock Grid.Row="2" Grid.Column="1" Text="(Configure in Simulated Users tab)" VerticalAlignment="Center" Margin="5" FontStyle="Italic" Foreground="Gray"/>
                                <Button Grid.Row="2" Grid.Column="2" Name="btnConfigureSimulated" Content="Configure" Style="{StaticResource ModernButton}" Margin="5" Width="120" IsEnabled="False"/>
                                
                                <CheckBox Grid.Row="3" Grid.Column="1" Name="chkShowTrace" Content="Show detailed filter evaluation trace" Margin="5" VerticalAlignment="Center"/>
                            </Grid>
                        </GroupBox>
                        
                        <!-- Actions -->
                        <GroupBox Header="Actions" Style="{StaticResource ModernGroupBox}">
                            <StackPanel Orientation="Horizontal" HorizontalAlignment="Center">
                                <Button Name="btnValidate" Content="▶ Run Validation" Style="{StaticResource ModernButton}" Margin="5" Width="150" Height="40" FontSize="15"/>
                                <Button Name="btnClear" Content="✖ Clear Results" Style="{StaticResource ModernButton}" Margin="5" Width="150" Height="40" Background="#666666"/>
                                <Button Name="btnExport" Content="📊 Export to CSV" Style="{StaticResource ModernButton}" Margin="5" Width="150" Height="40" Background="{StaticResource SuccessBrush}" IsEnabled="False"/>
                            </StackPanel>
                        </GroupBox>
                    </StackPanel>
                </ScrollViewer>
            </TabItem>
            
            <!-- Results Tab -->
            <TabItem Header="Results" Name="tabResults" FontSize="14" FontWeight="SemiBold">
                <Grid>
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>
                    
                    <!-- Summary Cards -->
                    <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="10">
                        <Border Background="White" CornerRadius="6" Padding="15" Margin="5" BorderBrush="{StaticResource BorderBrush}" BorderThickness="1" Width="180">
                            <StackPanel>
                                <TextBlock Text="Total Mappings" FontSize="12" Foreground="Gray"/>
                                <TextBlock Name="txtTotalMappings" Text="0" FontSize="28" FontWeight="Bold" Foreground="{StaticResource PrimaryBrush}"/>
                            </StackPanel>
                        </Border>
                        <Border Background="White" CornerRadius="6" Padding="15" Margin="5" BorderBrush="{StaticResource BorderBrush}" BorderThickness="1" Width="180">
                            <StackPanel>
                                <TextBlock Text="Users Tested" FontSize="12" Foreground="Gray"/>
                                <TextBlock Name="txtUsersTested" Text="0" FontSize="28" FontWeight="Bold" Foreground="{StaticResource AccentBrush}"/>
                            </StackPanel>
                        </Border>
                        <Border Background="White" CornerRadius="6" Padding="15" Margin="5" BorderBrush="{StaticResource BorderBrush}" BorderThickness="1" Width="180">
                            <StackPanel>
                                <TextBlock Text="Conflicts" FontSize="12" Foreground="Gray"/>
                                <TextBlock Name="txtConflicts" Text="0" FontSize="28" FontWeight="Bold" Foreground="{StaticResource ErrorBrush}"/>
                            </StackPanel>
                        </Border>
                        <Border Background="White" CornerRadius="6" Padding="15" Margin="5" BorderBrush="{StaticResource BorderBrush}" BorderThickness="1" Width="180">
                            <StackPanel>
                                <TextBlock Text="Warnings" FontSize="12" Foreground="Gray"/>
                                <TextBlock Name="txtWarnings" Text="0" FontSize="28" FontWeight="Bold" Foreground="{StaticResource WarningBrush}"/>
                            </StackPanel>
                        </Border>
                    </StackPanel>
                    
                    <!-- Results Grid -->
                    <DataGrid Grid.Row="1" Name="dgResults" Style="{StaticResource ModernDataGrid}" Margin="10">
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="User" Binding="{Binding Subject}" Width="150"/>
                            <DataGridTextColumn Header="Drive" Binding="{Binding DriveLetter}" Width="60"/>
                            <DataGridTextColumn Header="Path" Binding="{Binding Path}" Width="*" MinWidth="200"/>
                            <DataGridTextColumn Header="Label" Binding="{Binding Label}" Width="150"/>
                            <DataGridTextColumn Header="Action" Binding="{Binding Action}" Width="80"/>
                            <DataGridCheckBoxColumn Header="Applies" Binding="{Binding Applies}" Width="80"/>
                            <DataGridCheckBoxColumn Header="Disabled" Binding="{Binding IsDisabled}" Width="80"/>
                        </DataGrid.Columns>
                    </DataGrid>
                </Grid>
            </TabItem>
            
            <!-- Conflicts Tab -->
            <TabItem Header="Conflicts" Name="tabConflicts" FontSize="14" FontWeight="SemiBold">
                <Grid Margin="10">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>
                    
                    <TextBlock Grid.Row="0" Text="Drive letter conflicts (same user receiving multiple mappings for the same letter):" 
                               FontSize="13" Margin="5" FontWeight="SemiBold"/>
                    
                    <DataGrid Grid.Row="1" Name="dgConflicts" Style="{StaticResource ModernDataGrid}" Margin="5">
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="User" Binding="{Binding User}" Width="150"/>
                            <DataGridTextColumn Header="Drive Letter" Binding="{Binding DriveLetter}" Width="100"/>
                            <DataGridTextColumn Header="Conflicting Paths" Binding="{Binding Paths}" Width="*"/>
                            <DataGridTextColumn Header="Count" Binding="{Binding Count}" Width="80"/>
                        </DataGrid.Columns>
                    </DataGrid>
                </Grid>
            </TabItem>
            
            <!-- Trace Tab -->
            <TabItem Header="Filter Trace" Name="tabTrace" FontSize="14" FontWeight="SemiBold">
                <Grid Margin="10">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>
                    
                    <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="5">
                        <TextBlock Text="Filter for:" VerticalAlignment="Center" Margin="5"/>
                        <ComboBox Name="cmbTraceUser" Style="{StaticResource ModernComboBox}" Width="200" Margin="5"/>
                        <ComboBox Name="cmbTraceDrive" Style="{StaticResource ModernComboBox}" Width="150" Margin="5"/>
                        <Button Name="btnRefreshTrace" Content="Refresh" Style="{StaticResource ModernButton}" Margin="5" Width="100"/>
                    </StackPanel>
                    
                    <TextBox Grid.Row="1" Name="txtTrace" 
                             FontFamily="Consolas" 
                             FontSize="12" 
                             IsReadOnly="True" 
                             VerticalScrollBarVisibility="Auto" 
                             HorizontalScrollBarVisibility="Auto"
                             Background="#1E1E1E"
                             Foreground="#D4D4D4"
                             Padding="10"
                             Margin="5"/>
                </Grid>
            </TabItem>
            
            <!-- Warnings Tab -->
            <TabItem Header="Warnings" Name="tabWarnings" FontSize="14" FontWeight="SemiBold">
                <Grid Margin="10">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>
                    
                    <Border Grid.Row="0" Background="#FFF4CE" BorderBrush="{StaticResource WarningBrush}" BorderThickness="1" CornerRadius="4" Padding="10" Margin="5">
                        <StackPanel Orientation="Horizontal">
                            <TextBlock Text="⚠" FontSize="20" Foreground="{StaticResource WarningBrush}" Margin="0,0,10,0"/>
                            <TextBlock Text="The following filters could not be fully verified. Manual verification may be required." 
                                       FontSize="13" VerticalAlignment="Center" TextWrapping="Wrap"/>
                        </StackPanel>
                    </Border>
                    
                    <ListBox Grid.Row="1" Name="lstWarnings" 
                             FontFamily="Segoe UI" 
                             FontSize="12" 
                             Margin="5" 
                             Background="White"
                             BorderBrush="{StaticResource BorderBrush}"
                             BorderThickness="1"/>
                </Grid>
            </TabItem>
            
            <!-- Simulated Users Tab -->
            <TabItem Header="Simulated Users" Name="tabSimulated" FontSize="14" FontWeight="SemiBold">
                <Grid Margin="10">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>
                    
                    <TextBlock Grid.Row="0" Text="Define hypothetical users for testing scenarios that don't exist in AD yet:" 
                               FontSize="13" Margin="5" FontWeight="SemiBold" TextWrapping="Wrap"/>
                    
                    <DataGrid Grid.Row="1" Name="dgSimulatedUsers" Style="{StaticResource ModernDataGrid}" Margin="5" IsReadOnly="False">
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="Name" Binding="{Binding Name}" Width="150"/>
                            <DataGridTextColumn Header="Distinguished Name" Binding="{Binding DN}" Width="*" MinWidth="200"/>
                            <DataGridTextColumn Header="Member Of Groups" Binding="{Binding Groups}" Width="200"/>
                            <DataGridTextColumn Header="Computer" Binding="{Binding Computer}" Width="150"/>
                            <DataGridTextColumn Header="Site" Binding="{Binding Site}" Width="100"/>
                        </DataGrid.Columns>
                    </DataGrid>
                    
                    <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Center" Margin="5">
                        <Button Name="btnAddSimulated" Content="➕ Add User" Style="{StaticResource ModernButton}" Margin="5" Width="120"/>
                        <Button Name="btnRemoveSimulated" Content="➖ Remove Selected" Style="{StaticResource ModernButton}" Margin="5" Width="140" Background="#666666"/>
                        <Button Name="btnLoadTemplate" Content="📄 Load Template" Style="{StaticResource ModernButton}" Margin="5" Width="140" Background="{StaticResource AccentBrush}"/>
                    </StackPanel>
                </Grid>
            </TabItem>
        </TabControl>
        
        <!-- Status Bar -->
        <Border Grid.Row="2" Background="#E0E0E0" CornerRadius="4" Padding="10" Margin="0,10,0,0">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                
                <TextBlock Grid.Column="0" Name="txtStatus" Text="Ready" FontSize="12" VerticalAlignment="Center"/>
                <ProgressBar Grid.Column="1" Name="progressBar" Height="20" Margin="10,0" Visibility="Collapsed"/>
                <TextBlock Grid.Column="2" Name="txtVersion" Text="v1.0" FontSize="11" VerticalAlignment="Center" Foreground="Gray"/>
            </Grid>
        </Border>
    </Grid>
</Window>
"@

# ---------------------------------------------------------------------------
# Load XAML and get controls
# ---------------------------------------------------------------------------
$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

# Get all named controls
$controls = @{}
$xaml.SelectNodes("//*[@Name]") | ForEach-Object {
    $controls[$_.Name] = $window.FindName($_.Name)
}

# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------
function Show-Status {
    param([string]$Message, [string]$Type = "Info")
    
    $controls.txtStatus.Text = $Message
    
    switch ($Type) {
        "Success" { $controls.txtStatus.Foreground = "#107C10" }
        "Error"   { $controls.txtStatus.Foreground = "#E81123" }
        "Warning" { $controls.txtStatus.Foreground = "#FF8C00" }
        default   { $controls.txtStatus.Foreground = "#000000" }
    }
    
    $window.Dispatcher.Invoke([Action]{}, [Windows.Threading.DispatcherPriority]::Background)
}

function Show-Progress {
    param([bool]$Show)
    
    if ($Show) {
        $controls.progressBar.Visibility = "Visible"
        $controls.progressBar.IsIndeterminate = $true
    } else {
        $controls.progressBar.Visibility = "Collapsed"
        $controls.progressBar.IsIndeterminate = $false
    }
}

function Test-Prerequisites {
    $missing = @()
    
    if (-not (Test-Path $script:BackendScriptPath)) {
        $missing += "Backend validation script not found at: $script:BackendScriptPath"
    }
    
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        $missing += "ActiveDirectory PowerShell module (install RSAT)"
    }
    
    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        $missing += "GroupPolicy PowerShell module (install RSAT)"
    }
    
    if ($missing.Count -gt 0) {
        $msg = "Missing prerequisites:`n`n" + ($missing -join "`n")
        [System.Windows.MessageBox]::Show($msg, "Prerequisites Required", "OK", "Warning")
        return $false
    }
    
    return $true
}

function Get-AdDomain {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $domain = (Get-ADDomain).DNSRoot
        return $domain
    }
    catch {
        return $env:USERDNSDOMAIN
    }
}

function Browse-Gpo {
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        $domain = $controls.txtDomain.Text
        
        if (-not $domain) {
            [System.Windows.MessageBox]::Show("Please specify a domain first.", "Domain Required", "OK", "Warning")
            return
        }
        
        Show-Status "Loading GPOs from $domain..." "Info"
        Show-Progress $true
        
        $gpos = Get-GPO -All -Domain $domain | Select-Object DisplayName | Sort-Object DisplayName
        
        Show-Progress $false
        
        if ($gpos.Count -eq 0) {
            [System.Windows.MessageBox]::Show("No GPOs found in domain.", "No GPOs", "OK", "Information")
            return
        }
        
        # Create selection dialog
        $selectionWindow = New-Object System.Windows.Window
        $selectionWindow.Title = "Select GPO"
        $selectionWindow.Width = 600
        $selectionWindow.Height = 500
        $selectionWindow.WindowStartupLocation = "CenterOwner"
        $selectionWindow.Owner = $window
        
        $grid = New-Object System.Windows.Controls.Grid
        $grid.Margin = "10"
        
        $row1 = New-Object System.Windows.Controls.RowDefinition
        $row1.Height = "Auto"
        $row2 = New-Object System.Windows.Controls.RowDefinition
        $row3 = New-Object System.Windows.Controls.RowDefinition
        $row3.Height = "Auto"
        
        $grid.RowDefinitions.Add($row1)
        $grid.RowDefinitions.Add($row2)
        $grid.RowDefinitions.Add($row3)
        
        $searchBox = New-Object System.Windows.Controls.TextBox
        $searchBox.Margin = "0,0,0,10"
        $searchBox.Padding = "5"
        [System.Windows.Controls.Grid]::SetRow($searchBox, 0)
        
        $listBox = New-Object System.Windows.Controls.ListBox
        [System.Windows.Controls.Grid]::SetRow($listBox, 1)
        $listBox.Margin = "0,0,0,10"
        
        foreach ($gpo in $gpos) {
            $listBox.Items.Add($gpo.DisplayName) | Out-Null
        }
        
        $searchBox.Add_TextChanged({
            $filter = $searchBox.Text
            $listBox.Items.Clear()
            foreach ($gpo in $gpos) {
                if ($gpo.DisplayName -like "*$filter*") {
                    $listBox.Items.Add($gpo.DisplayName) | Out-Null
                }
            }
        })
        
        $buttonPanel = New-Object System.Windows.Controls.StackPanel
        $buttonPanel.Orientation = "Horizontal"
        $buttonPanel.HorizontalAlignment = "Right"
        [System.Windows.Controls.Grid]::SetRow($buttonPanel, 2)
        
        $okButton = New-Object System.Windows.Controls.Button
        $okButton.Content = "Select"
        $okButton.Width = 80
        $okButton.Margin = "5"
        $okButton.IsDefault = $true
        $okButton.Add_Click({
            if ($listBox.SelectedItem) {
                $controls.txtGpoName.Text = $listBox.SelectedItem
                $selectionWindow.DialogResult = $true
                $selectionWindow.Close()
            }
        })
        
        $cancelButton = New-Object System.Windows.Controls.Button
        $cancelButton.Content = "Cancel"
        $cancelButton.Width = 80
        $cancelButton.Margin = "5"
        $cancelButton.IsCancel = $true
        $cancelButton.Add_Click({ $selectionWindow.Close() })
        
        $buttonPanel.AddChild($okButton)
        $buttonPanel.AddChild($cancelButton)
        
        $grid.AddChild($searchBox)
        $grid.AddChild($listBox)
        $grid.AddChild($buttonPanel)
        
        $selectionWindow.Content = $grid
        $selectionWindow.ShowDialog() | Out-Null
        
        Show-Status "Ready" "Info"
    }
    catch {
        Show-Progress $false
        [System.Windows.MessageBox]::Show("Failed to load GPOs: $($_.Exception.Message)", "Error", "OK", "Error")
        Show-Status "Error loading GPOs" "Error"
    }
}

function Invoke-Validation {
    if (-not (Test-Prerequisites)) { return }
    
    # Validate inputs
    $hasGpo = $controls.txtGpoName.Text -ne ""
    $hasXml = $controls.txtXmlPath.Text -ne ""
    
    if (-not $hasGpo -and -not $hasXml) {
        [System.Windows.MessageBox]::Show("Please specify either a GPO name or Drives.xml path.", "Input Required", "OK", "Warning")
        return
    }
    
    $hasUsers = $false
    $targetUsers = $null
    $targetOU = $null
    $simulatedUsers = $null
    
    if ($controls.rbTargetUsers.IsChecked) {
        $userList = $controls.txtTargetUsers.Text
        if ($userList) {
            $targetUsers = $userList -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            $hasUsers = $targetUsers.Count -gt 0
        }
    }
    elseif ($controls.rbTargetOU.IsChecked) {
        $targetOU = $controls.txtTargetOU.Text
        $hasUsers = $targetOU -ne ""
    }
    elseif ($controls.rbSimulated.IsChecked) {
        $simulatedUsers = @()
        foreach ($item in $controls.dgSimulatedUsers.Items) {
            if ($item.Name) {
                $simulatedUsers += @{
                    Name = $item.Name
                    DistinguishedName = $item.DN
                    MemberOfGroups = if ($item.Groups) { $item.Groups -split ';' } else { @() }
                    ComputerName = $item.Computer
                    Site = $item.Site
                }
            }
        }
        $hasUsers = $simulatedUsers.Count -gt 0
    }
    
    if (-not $hasUsers) {
        [System.Windows.MessageBox]::Show("Please specify test subjects (users, OU, or simulated users).", "Input Required", "OK", "Warning")
        return
    }
    
    # Build parameters
    $params = @{
        ReturnObject = $true
        ShowFilterTrace = $controls.chkShowTrace.IsChecked
    }
    
    if ($hasGpo) {
        $params.GpoName = $controls.txtGpoName.Text
        $params.Domain = $controls.txtDomain.Text
    } else {
        $params.DrivesXmlPath = $controls.txtXmlPath.Text
    }
    
    if ($targetUsers) { $params.TargetUsers = $targetUsers }
    if ($targetOU) { $params.TargetOU = $targetOU }
    if ($simulatedUsers) { $params.SimulatedUsers = $simulatedUsers }
    
    # Execute validation
    Show-Status "Running validation..." "Info"
    Show-Progress $true
    $controls.btnValidate.IsEnabled = $false
    
    try {
        $script:ValidationResults = & $script:BackendScriptPath @params
        
        if (-not $script:ValidationResults) {
            throw "Validation returned no results"
        }
        
        Update-ResultsDisplay
        
        $controls.tabResults.IsSelected = $true
        $controls.btnExport.IsEnabled = $true
        
        Show-Status "Validation completed successfully" "Success"
    }
    catch {
        [System.Windows.MessageBox]::Show("Validation failed: $($_.Exception.Message)", "Error", "OK", "Error")
        Show-Status "Validation failed" "Error"
    }
    finally {
        Show-Progress $false
        $controls.btnValidate.IsEnabled = $true
    }
}

function Update-ResultsDisplay {
    if (-not $script:ValidationResults) { return }
    
    $results = $script:ValidationResults.Results
    
    # Update summary cards
    $totalMappings = ($results | Select-Object -Unique Subject, DriveLetter).Count
    $usersTested = ($results | Select-Object -Unique Subject).Count
    $conflictCount = if ($script:ValidationResults.Conflicts) { $script:ValidationResults.Conflicts.Count } else { 0 }
    $warningCount = if ($script:ValidationResults.Warnings) { $script:ValidationResults.Warnings.Count } else { 0 }
    
    $controls.txtTotalMappings.Text = $totalMappings
    $controls.txtUsersTested.Text = $usersTested
    $controls.txtConflicts.Text = $conflictCount
    $controls.txtWarnings.Text = $warningCount
    
    # Populate results grid
    $controls.dgResults.ItemsSource = $results
    
    # Populate conflicts grid
    if ($script:ValidationResults.Conflicts) {
        $conflictData = @()
        foreach ($conflict in $script:ValidationResults.Conflicts) {
            $parts = $conflict.Name -split ', '
            $user = $parts[0]
            $driveLetter = $parts[1]
            $paths = ($conflict.Group | ForEach-Object { $_.Path }) -join ' | '
            
            $conflictData += [pscustomobject]@{
                User = $user
                DriveLetter = $driveLetter
                Paths = $paths
                Count = $conflict.Count
            }
        }
        $controls.dgConflicts.ItemsSource = $conflictData
    }
    
    # Populate warnings
    if ($script:ValidationResults.Warnings) {
        $controls.lstWarnings.Items.Clear()
        foreach ($warning in $script:ValidationResults.Warnings) {
            $controls.lstWarnings.Items.Add($warning) | Out-Null
        }
    }
    
    # Populate trace filters
    $controls.cmbTraceUser.Items.Clear()
    $controls.cmbTraceDrive.Items.Clear()
    
    $results | Select-Object -Unique Subject | ForEach-Object {
        $controls.cmbTraceUser.Items.Add($_.Subject) | Out-Null
    }
    
    $results | Select-Object -Unique DriveLetter | ForEach-Object {
        $controls.cmbTraceDrive.Items.Add($_.DriveLetter) | Out-Null
    }
    
    if ($controls.cmbTraceUser.Items.Count -gt 0) {
        $controls.cmbTraceUser.SelectedIndex = 0
    }
    if ($controls.cmbTraceDrive.Items.Count -gt 0) {
        $controls.cmbTraceDrive.SelectedIndex = 0
    }
    
    Update-TraceDisplay
}

function Update-TraceDisplay {
    if (-not $script:ValidationResults) { return }
    
    $selectedUser = $controls.cmbTraceUser.SelectedItem
    $selectedDrive = $controls.cmbTraceDrive.SelectedItem
    
    if (-not $selectedUser -or -not $selectedDrive) { return }
    
    $result = $script:ValidationResults.Results | 
        Where-Object { $_.Subject -eq $selectedUser -and $_.DriveLetter -eq $selectedDrive } | 
        Select-Object -First 1
    
    if ($result) {
        $controls.txtTrace.Text = $result.Trace
    }
}

function Export-Results {
    if (-not $script:ValidationResults) { return }
    
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
    $saveDialog.DefaultExt = "csv"
    $saveDialog.FileName = "GPO-DriveMap-Validation-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    
    if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $script:ValidationResults.Results | 
                Select-Object Subject, DriveLetter, Path, Label, Action, Applies, IsDisabled |
                Export-Csv -Path $saveDialog.FileName -NoTypeInformation -Encoding UTF8
            
            [System.Windows.MessageBox]::Show("Results exported successfully to:`n$($saveDialog.FileName)", "Export Complete", "OK", "Information")
            Show-Status "Results exported successfully" "Success"
        }
        catch {
            [System.Windows.MessageBox]::Show("Export failed: $($_.Exception.Message)", "Error", "OK", "Error")
            Show-Status "Export failed" "Error"
        }
    }
}

function Clear-Results {
    $script:ValidationResults = $null
    
    $controls.dgResults.ItemsSource = $null
    $controls.dgConflicts.ItemsSource = $null
    $controls.lstWarnings.Items.Clear()
    $controls.txtTrace.Text = ""
    $controls.cmbTraceUser.Items.Clear()
    $controls.cmbTraceDrive.Items.Clear()
    
    $controls.txtTotalMappings.Text = "0"
    $controls.txtUsersTested.Text = "0"
    $controls.txtConflicts.Text = "0"
    $controls.txtWarnings.Text = "0"
    
    $controls.btnExport.IsEnabled = $false
    
    Show-Status "Results cleared" "Info"
}

# ---------------------------------------------------------------------------
# Event Handlers
# ---------------------------------------------------------------------------

$controls.btnDetectDomain.Add_Click({
    $domain = Get-AdDomain
    if ($domain) {
        $controls.txtDomain.Text = $domain
        Show-Status "Domain detected: $domain" "Success"
    } else {
        Show-Status "Could not detect domain" "Warning"
    }
})

$controls.btnBrowseGpo.Add_Click({ Browse-Gpo })

$controls.btnBrowseXml.Add_Click({
    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "XML Files (*.xml)|*.xml|All Files (*.*)|*.*"
    $openDialog.Title = "Select Drives.xml"
    
    if ($openDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $controls.txtXmlPath.Text = $openDialog.FileName
    }
})

$controls.rbTargetUsers.Add_Checked({
    $controls.txtTargetUsers.IsEnabled = $true
    $controls.btnBrowseUsers.IsEnabled = $true
    $controls.txtTargetOU.IsEnabled = $false
    $controls.btnBrowseOU.IsEnabled = $false
    $controls.btnConfigureSimulated.IsEnabled = $false
})

$controls.rbTargetOU.Add_Checked({
    $controls.txtTargetUsers.IsEnabled = $false
    $controls.btnBrowseUsers.IsEnabled = $false
    $controls.txtTargetOU.IsEnabled = $true
    $controls.btnBrowseOU.IsEnabled = $true
    $controls.btnConfigureSimulated.IsEnabled = $false
})

$controls.rbSimulated.Add_Checked({
    $controls.txtTargetUsers.IsEnabled = $false
    $controls.btnBrowseUsers.IsEnabled = $false
    $controls.txtTargetOU.IsEnabled = $false
    $controls.btnBrowseOU.IsEnabled = $false
    $controls.btnConfigureSimulated.IsEnabled = $true
})

$controls.btnValidate.Add_Click({ Invoke-Validation })
$controls.btnClear.Add_Click({ Clear-Results })
$controls.btnExport.Add_Click({ Export-Results })

$controls.btnRefreshTrace.Add_Click({ Update-TraceDisplay })
$controls.cmbTraceUser.Add_SelectionChanged({ Update-TraceDisplay })
$controls.cmbTraceDrive.Add_SelectionChanged({ Update-TraceDisplay })

$controls.btnAddSimulated.Add_Click({
    $newUser = [pscustomobject]@{
        Name = ""
        DN = ""
        Groups = ""
        Computer = ""
        Site = ""
    }
    
    if (-not $controls.dgSimulatedUsers.ItemsSource) {
        $controls.dgSimulatedUsers.ItemsSource = New-Object System.Collections.ObjectModel.ObservableCollection[object]
    }
    
    $controls.dgSimulatedUsers.ItemsSource.Add($newUser)
})

$controls.btnRemoveSimulated.Add_Click({
    if ($controls.dgSimulatedUsers.SelectedItem) {
        $controls.dgSimulatedUsers.ItemsSource.Remove($controls.dgSimulatedUsers.SelectedItem)
    }
})

# ---------------------------------------------------------------------------
# Initialize
# ---------------------------------------------------------------------------

# Auto-detect domain
$initialDomain = Get-AdDomain
if ($initialDomain) {
    $controls.txtDomain.Text = $initialDomain
}

# Initialize simulated users grid with observable collection
$controls.dgSimulatedUsers.ItemsSource = New-Object System.Collections.ObjectModel.ObservableCollection[object]

Show-Status "Ready - Configure settings and click 'Run Validation'" "Info"

# Show window
$window.ShowDialog() | Out-Null
