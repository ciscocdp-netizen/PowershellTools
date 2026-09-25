#Requires -Version 5.1
<#
.SYNOPSIS
    GPO Drive Mapping Validator & Manager - Full-Featured WPF GUI

.DESCRIPTION
    Modern dark-themed WPF GUI for validating, testing, and managing Group Policy
    Preference (GPP) drive mappings with comprehensive Item-Level Targeting (ILT)
    filter evaluation, user simulation, conflict detection, and GPO comparison.

    Architecture based on proven WPF patterns from DHCP-Manager-v2-FULL.ps1 by Anthony Blake.

.NOTES
    Requires: PowerShell 5.1+ on Windows Server 2016/2019/2022 or Windows 10/11
              RSAT ActiveDirectory module (for live AD queries)
              RSAT GroupPolicy module (for GPO enumeration)
    
    Version: 2.0
    Author: Generated from validated reference architecture
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$script:Window = $null
$script:LoadedGpo = $null
$script:CurrentDomain = $env:USERDNSDOMAIN
$script:MappingsData = New-Object System.Collections.ObjectModel.ObservableCollection[object]
$script:ActionLogEntries = New-Object System.Collections.ObjectModel.ObservableCollection[object]
$script:ValidationResults = @()
$script:ConflictData = @()

#region Assembly Loading
try {
    Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
    Add-Type -AssemblyName PresentationCore -ErrorAction Stop
    Add-Type -AssemblyName WindowsBase -ErrorAction Stop
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    Add-Type -AssemblyName System.Drawing -ErrorAction Stop
}
catch {
    [System.Windows.Forms.MessageBox]::Show(
        "Failed to load required WPF assemblies: $($_.Exception.Message)",
        "Fatal Error",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
    exit 1
}
#endregion

#region Module Validation
function Test-RequiredModules {
    $modules = @('ActiveDirectory', 'GroupPolicy')
    $missing = @()
    
    foreach ($mod in $modules) {
        if (-not (Get-Module -ListAvailable -Name $mod)) {
            $missing += $mod
        }
    }
    
    if ($missing.Count -gt 0) {
        $msg = "Required RSAT modules not found: $($missing -join ', ')`n`n" +
               "Install RSAT tools for Windows Server or Windows 10/11 to use this application."
        [System.Windows.Forms.MessageBox]::Show($msg, "Missing Dependencies", 
            [System.Windows.Forms.MessageBoxButtons]::OK, 
            [System.Windows.Forms.MessageBoxIcon]::Warning)
        return $false
    }
    
    return $true
}

if (-not (Test-RequiredModules)) {
    exit 1
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module GroupPolicy -ErrorAction Stop
}
catch {
    [System.Windows.Forms.MessageBox]::Show(
        "Failed to import required modules: $($_.Exception.Message)",
        "Module Error",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
    exit 1
}
#endregion

#region XAML Definition
$xaml = @'
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="GPO Drive Mapping Validator &amp; Manager v2.0"
    WindowStartupLocation="CenterScreen"
    Width="1600" Height="900"
    MinWidth="1200" MinHeight="700"
    Background="#1A1D23">

    <Window.Resources>
        <!-- Color Palette (Dark Theme) -->
        <SolidColorBrush x:Key="BgDeep" Color="#1A1D23"/>
        <SolidColorBrush x:Key="BgPanel" Color="#22262E"/>
        <SolidColorBrush x:Key="BgCard" Color="#2A2F3A"/>
        <SolidColorBrush x:Key="BorderBrush" Color="#3A3F4A"/>
        <SolidColorBrush x:Key="Accent" Color="#2196F3"/>
        <SolidColorBrush x:Key="AccentHover" Color="#42A5F5"/>
        <SolidColorBrush x:Key="Success" Color="#4CAF50"/>
        <SolidColorBrush x:Key="Warning" Color="#FF9800"/>
        <SolidColorBrush x:Key="Danger" Color="#F44336"/>
        <SolidColorBrush x:Key="TextPrimary" Color="#E8EAF0"/>
        <SolidColorBrush x:Key="TextSecond" Color="#9AA3B2"/>

        <!-- Button Style -->
        <Style TargetType="Button">
            <Setter Property="Background" Value="{StaticResource Accent}"/>
            <Setter Property="Foreground" Value="{StaticResource TextPrimary}"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="12,6"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="FontWeight" Value="Medium"/>
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
                    <Setter Property="Background" Value="{StaticResource AccentHover}"/>
                </Trigger>
                <Trigger Property="IsEnabled" Value="False">
                    <Setter Property="Opacity" Value="0.5"/>
                    <Setter Property="Cursor" Value="Arrow"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <!-- TextBox Style -->
        <Style TargetType="TextBox">
            <Setter Property="Background" Value="{StaticResource BgPanel}"/>
            <Setter Property="Foreground" Value="{StaticResource TextPrimary}"/>
            <Setter Property="BorderBrush" Value="{StaticResource BorderBrush}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="8,6"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="CaretBrush" Value="{StaticResource Accent}"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="TextBox">
                        <Border Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="4">
                            <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsFocused" Value="True">
                    <Setter Property="BorderBrush" Value="{StaticResource Accent}"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <!-- ComboBox Style -->
        <Style TargetType="ComboBox">
            <Setter Property="Background" Value="{StaticResource BgPanel}"/>
            <Setter Property="Foreground" Value="{StaticResource TextPrimary}"/>
            <Setter Property="BorderBrush" Value="{StaticResource BorderBrush}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="8,6"/>
            <Setter Property="FontSize" Value="13"/>
        </Style>

        <!-- DataGrid Style -->
        <Style TargetType="DataGrid">
            <Setter Property="Background" Value="{StaticResource BgCard}"/>
            <Setter Property="Foreground" Value="{StaticResource TextPrimary}"/>
            <Setter Property="BorderBrush" Value="{StaticResource BorderBrush}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="GridLinesVisibility" Value="None"/>
            <Setter Property="HeadersVisibility" Value="Column"/>
            <Setter Property="AutoGenerateColumns" Value="False"/>
            <Setter Property="CanUserAddRows" Value="False"/>
            <Setter Property="CanUserDeleteRows" Value="False"/>
            <Setter Property="SelectionMode" Value="Single"/>
            <Setter Property="RowBackground" Value="{StaticResource BgCard}"/>
            <Setter Property="AlternatingRowBackground" Value="#252A35"/>
            <Setter Property="HorizontalGridLinesBrush" Value="{StaticResource BorderBrush}"/>
            <Setter Property="VerticalGridLinesBrush" Value="{StaticResource BorderBrush}"/>
        </Style>

        <Style TargetType="DataGridColumnHeader">
            <Setter Property="Background" Value="{StaticResource BgPanel}"/>
            <Setter Property="Foreground" Value="{StaticResource TextPrimary}"/>
            <Setter Property="Padding" Value="10,8"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="BorderBrush" Value="{StaticResource BorderBrush}"/>
            <Setter Property="BorderThickness" Value="0,0,1,1"/>
        </Style>

        <Style TargetType="DataGridCell">
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="8,6"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="DataGridCell">
                        <Border Background="{TemplateBinding Background}" Padding="{TemplateBinding Padding}">
                            <ContentPresenter VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsSelected" Value="True">
                    <Setter Property="Background" Value="#1565C0"/>
                    <Setter Property="Foreground" Value="{StaticResource TextPrimary}"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <!-- TabControl Style -->
        <Style TargetType="TabControl">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="BorderThickness" Value="0"/>
        </Style>

        <Style TargetType="TabItem">
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="TabItem">
                        <Border Name="Border" 
                                Background="{StaticResource BgPanel}"
                                BorderThickness="0,0,1,0"
                                BorderBrush="{StaticResource BorderBrush}"
                                Padding="16,10"
                                Margin="0,0,2,0">
                            <ContentPresenter ContentSource="Header"
                                            VerticalAlignment="Center"
                                            HorizontalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsSelected" Value="True">
                                <Setter TargetName="Border" Property="Background" Value="{StaticResource Accent}"/>
                            </Trigger>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Border" Property="Background" Value="{StaticResource AccentHover}"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Setter Property="Foreground" Value="{StaticResource TextPrimary}"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="FontWeight" Value="Medium"/>
        </Style>

        <!-- TextBlock Default Style -->
        <Style TargetType="TextBlock">
            <Setter Property="Foreground" Value="{StaticResource TextPrimary}"/>
            <Setter Property="FontSize" Value="13"/>
        </Style>

        <!-- Label Style -->
        <Style TargetType="Label">
            <Setter Property="Foreground" Value="{StaticResource TextPrimary}"/>
            <Setter Property="FontSize" Value="13"/>
        </Style>

        <!-- CheckBox Style -->
        <Style TargetType="CheckBox">
            <Setter Property="Foreground" Value="{StaticResource TextPrimary}"/>
            <Setter Property="FontSize" Value="13"/>
        </Style>
    </Window.Resources>

    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="60"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="32"/>
        </Grid.RowDefinitions>

        <!-- TOP TOOLBAR -->
        <Border Grid.Row="0" Background="{StaticResource BgPanel}" BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,0,0,1">
            <Grid Margin="16,0">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>

                <StackPanel Grid.Column="0" Orientation="Horizontal" VerticalAlignment="Center">
                    <TextBlock Text="GPO Drive Mapping Validator" FontSize="18" FontWeight="Bold" 
                               Foreground="{StaticResource Accent}" VerticalAlignment="Center"/>
                </StackPanel>

                <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center" HorizontalAlignment="Right">
                    <Label Content="Domain:" VerticalAlignment="Center" Margin="0,0,8,0"/>
                    <ComboBox x:Name="ComboDomain" Width="200" VerticalAlignment="Center" Margin="0,0,16,0"/>
                    
                    <Label Content="GPO:" VerticalAlignment="Center" Margin="0,0,8,0"/>
                    <ComboBox x:Name="ComboGpo" Width="300" VerticalAlignment="Center" Margin="0,0,16,0" IsEnabled="False"/>
                    
                    <Button x:Name="BtnLoadGpo" Content="Load GPO" Width="100" Margin="0,0,8,0"/>
                    <Button x:Name="BtnRefresh" Content="🔄 Refresh" Width="90"/>
                </StackPanel>
            </Grid>
        </Border>

        <!-- MAIN CONTENT AREA -->
        <TabControl Grid.Row="1" Margin="0" x:Name="MainTabs">
            
            <!-- TAB 1: Drive Mappings -->
            <TabItem Header="📁 Drive Mappings">
                <Grid Background="{StaticResource BgDeep}">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>

                    <Border Grid.Row="0" Background="{StaticResource BgPanel}" Padding="16" Margin="8,8,8,0" CornerRadius="6">
                        <StackPanel>
                            <TextBlock Text="Current GPO Drive Mappings" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12"/>
                            <TextBlock x:Name="TxtGpoInfo" Text="No GPO loaded. Select a GPO from the toolbar above." 
                                       Foreground="{StaticResource TextSecond}" TextWrapping="Wrap"/>
                        </StackPanel>
                    </Border>

                    <DataGrid Grid.Row="1" x:Name="GridMappings" Margin="8" ItemsSource="{Binding}">
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="Drive Letter" Binding="{Binding DriveLetter}" Width="100"/>
                            <DataGridTextColumn Header="Path" Binding="{Binding Path}" Width="300"/>
                            <DataGridTextColumn Header="Label" Binding="{Binding Label}" Width="150"/>
                            <DataGridTextColumn Header="Action" Binding="{Binding Action}" Width="80"/>
                            <DataGridTextColumn Header="State" Binding="{Binding State}" Width="100"/>
                            <DataGridTextColumn Header="Has Filters" Binding="{Binding HasFilters}" Width="100"/>
                            <DataGridTextColumn Header="Filter Summary" Binding="{Binding FilterSummary}" Width="*"/>
                        </DataGrid.Columns>
                    </DataGrid>
                </Grid>
            </TabItem>

            <!-- TAB 2: User Validation -->
            <TabItem Header="👤 User Validation">
                <Grid Background="{StaticResource BgDeep}">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>

                    <Border Grid.Row="0" Background="{StaticResource BgPanel}" Padding="16" Margin="8,8,8,0" CornerRadius="6">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                            </Grid.RowDefinitions>

                            <TextBlock Grid.Row="0" Text="Test Drive Mappings Against Users" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,16"/>
                            
                            <Grid Grid.Row="1">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="Auto"/>
                                </Grid.RowDefinitions>

                                <Label Grid.Row="0" Grid.Column="0" Content="Test Mode:" VerticalAlignment="Center" Margin="0,0,8,8"/>
                                <ComboBox Grid.Row="0" Grid.Column="1" x:Name="ComboValidationMode" Margin="0,0,16,8">
                                    <ComboBoxItem Content="Single User (sAMAccountName)" IsSelected="True"/>
                                    <ComboBoxItem Content="All Users in OU (Distinguished Name)"/>
                                    <ComboBoxItem Content="User List (comma-separated sAMAccountNames)"/>
                                </ComboBox>

                                <Label Grid.Row="1" Grid.Column="0" Content="Input:" VerticalAlignment="Center" Margin="0,0,8,0"/>
                                <TextBox Grid.Row="1" Grid.Column="1" x:Name="TxtValidationInput" Margin="0,0,16,0" 
                                         TextWrapping="Wrap" AcceptsReturn="False"/>
                                <Button Grid.Row="1" Grid.Column="2" x:Name="BtnRunValidation" Content="▶ Validate" Width="120"/>
                            </Grid>
                        </Grid>
                    </Border>

                    <TabControl Grid.Row="1" Margin="8" x:Name="ValidationTabs">
                        <TabItem Header="Results Summary">
                            <DataGrid x:Name="GridValidationResults" ItemsSource="{Binding}">
                                <DataGrid.Columns>
                                    <DataGridTextColumn Header="User" Binding="{Binding Subject}" Width="150"/>
                                    <DataGridTextColumn Header="Drive Letter" Binding="{Binding DriveLetter}" Width="100"/>
                                    <DataGridTextColumn Header="Path" Binding="{Binding Path}" Width="250"/>
                                    <DataGridTextColumn Header="Label" Binding="{Binding Label}" Width="120"/>
                                    <DataGridTextColumn Header="Applies" Binding="{Binding Applies}" Width="80"/>
                                    <DataGridCheckBoxColumn Header="Disabled" Binding="{Binding IsDisabled}" Width="80"/>
                                </DataGrid.Columns>
                            </DataGrid>
                        </TabItem>
                        
                        <TabItem Header="Filter Trace">
                            <ScrollViewer VerticalScrollBarVisibility="Auto">
                                <TextBox x:Name="TxtFilterTrace" IsReadOnly="True" TextWrapping="Wrap" 
                                         FontFamily="Consolas" FontSize="11" Background="{StaticResource BgCard}"
                                         BorderThickness="0" Padding="12" VerticalScrollBarVisibility="Auto"/>
                            </ScrollViewer>
                        </TabItem>
                        
                        <TabItem Header="Conflicts">
                            <Grid>
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="*"/>
                                </Grid.RowDefinitions>
                                
                                <Border Grid.Row="0" Background="{StaticResource BgPanel}" Padding="12" Margin="8">
                                    <TextBlock x:Name="TxtConflictSummary" Text="No conflicts detected." 
                                               Foreground="{StaticResource Success}" FontWeight="SemiBold"/>
                                </Border>
                                
                                <DataGrid Grid.Row="1" x:Name="GridConflicts" Margin="8" ItemsSource="{Binding}">
                                    <DataGrid.Columns>
                                        <DataGridTextColumn Header="User" Binding="{Binding User}" Width="150"/>
                                        <DataGridTextColumn Header="Drive Letter" Binding="{Binding DriveLetter}" Width="100"/>
                                        <DataGridTextColumn Header="Conflicting Paths" Binding="{Binding Paths}" Width="*"/>
                                    </DataGrid.Columns>
                                </DataGrid>
                            </Grid>
                        </TabItem>

                        <TabItem Header="Warnings">
                            <ScrollViewer VerticalScrollBarVisibility="Auto">
                                <StackPanel x:Name="PanelWarnings" Margin="12">
                                    <TextBlock Text="No warnings." Foreground="{StaticResource Success}"/>
                                </StackPanel>
                            </ScrollViewer>
                        </TabItem>
                    </TabControl>
                </Grid>
            </TabItem>

            <!-- TAB 3: Filter Inspector -->
            <TabItem Header="🔍 Filter Inspector">
                <Grid Background="{StaticResource BgDeep}">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>

                    <Border Grid.Row="0" Background="{StaticResource BgPanel}" Padding="16" Margin="8,8,8,0" CornerRadius="6">
                        <StackPanel>
                            <TextBlock Text="Item-Level Targeting (ILT) Filter Inspector" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,8"/>
                            <TextBlock Text="Select a drive mapping from the grid below to view its detailed filter tree structure." 
                                       Foreground="{StaticResource TextSecond}" TextWrapping="Wrap"/>
                        </StackPanel>
                    </Border>

                    <Grid Grid.Row="1" Margin="8">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="2*"/>
                        </Grid.ColumnDefinitions>

                        <DataGrid Grid.Column="0" x:Name="GridFilterInspectorDrives" Margin="0,0,4,0" 
                                  SelectionChanged="GridFilterInspectorDrives_SelectionChanged">
                            <DataGrid.Columns>
                                <DataGridTextColumn Header="Drive" Binding="{Binding DriveLetter}" Width="60"/>
                                <DataGridTextColumn Header="Path" Binding="{Binding Path}" Width="*"/>
                            </DataGrid.Columns>
                        </DataGrid>

                        <Border Grid.Column="1" Background="{StaticResource BgCard}" CornerRadius="6" Padding="12" Margin="4,0,0,0">
                            <ScrollViewer VerticalScrollBarVisibility="Auto">
                                <TextBox x:Name="TxtFilterInspectorDetail" IsReadOnly="True" TextWrapping="Wrap"
                                         FontFamily="Consolas" FontSize="11" Background="Transparent" 
                                         BorderThickness="0" Foreground="{StaticResource TextPrimary}"/>
                            </ScrollViewer>
                        </Border>
                    </Grid>
                </Grid>
            </TabItem>

            <!-- TAB 4: GPO Comparison -->
            <TabItem Header="⚖ GPO Comparison">
                <Grid Background="{StaticResource BgDeep}">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>

                    <Border Grid.Row="0" Background="{StaticResource BgPanel}" Padding="16" Margin="8,8,8,0" CornerRadius="6">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                            </Grid.RowDefinitions>

                            <TextBlock Grid.Row="0" Text="Compare Drive Mappings Across GPOs" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,12"/>
                            
                            <Grid Grid.Row="1">
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>

                                <Label Grid.Column="0" Content="Compare with GPO:" VerticalAlignment="Center" Margin="0,0,8,0"/>
                                <ComboBox Grid.Column="1" x:Name="ComboCompareGpo" Margin="0,0,16,0"/>
                                <Button Grid.Column="2" x:Name="BtnCompare" Content="Compare" Width="100"/>
                            </Grid>
                        </Grid>
                    </Border>

                    <DataGrid Grid.Row="1" x:Name="GridComparison" Margin="8">
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="Drive Letter" Binding="{Binding DriveLetter}" Width="100"/>
                            <DataGridTextColumn Header="Current GPO Path" Binding="{Binding CurrentPath}" Width="*"/>
                            <DataGridTextColumn Header="Compare GPO Path" Binding="{Binding ComparePath}" Width="*"/>
                            <DataGridTextColumn Header="Status" Binding="{Binding Status}" Width="120"/>
                        </DataGrid.Columns>
                    </DataGrid>
                </Grid>
            </TabItem>

            <!-- TAB 5: Add Mapping Simulator -->
            <TabItem Header="➕ Add Mapping Simulator">
                <Grid Background="{StaticResource BgDeep}">
                    <ScrollViewer VerticalScrollBarVisibility="Auto">
                        <StackPanel Margin="16">
                            <Border Background="{StaticResource BgPanel}" Padding="16" CornerRadius="6" Margin="0,0,0,16">
                                <StackPanel>
                                    <TextBlock Text="Add New Drive Mapping (Simulation)" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,16"/>
                                    <TextBlock Text="Simulate adding a new drive mapping to the current GPO and test for conflicts." 
                                               Foreground="{StaticResource TextSecond}" TextWrapping="Wrap" Margin="0,0,0,16"/>

                                    <Grid>
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width="150"/>
                                            <ColumnDefinition Width="*"/>
                                        </Grid.ColumnDefinitions>
                                        <Grid.RowDefinitions>
                                            <RowDefinition Height="Auto"/>
                                            <RowDefinition Height="Auto"/>
                                            <RowDefinition Height="Auto"/>
                                            <RowDefinition Height="Auto"/>
                                            <RowDefinition Height="Auto"/>
                                        </Grid.RowDefinitions>

                                        <Label Grid.Row="0" Grid.Column="0" Content="Drive Letter:" Margin="0,0,0,12"/>
                                        <TextBox Grid.Row="0" Grid.Column="1" x:Name="TxtNewDriveLetter" Margin="0,0,0,12" MaxLength="2"/>

                                        <Label Grid.Row="1" Grid.Column="0" Content="UNC Path:" Margin="0,0,0,12"/>
                                        <TextBox Grid.Row="1" Grid.Column="1" x:Name="TxtNewPath" Margin="0,0,0,12"/>

                                        <Label Grid.Row="2" Grid.Column="0" Content="Label:" Margin="0,0,0,12"/>
                                        <TextBox Grid.Row="2" Grid.Column="1" x:Name="TxtNewLabel" Margin="0,0,0,12"/>

                                        <Label Grid.Row="3" Grid.Column="0" Content="Action:" Margin="0,0,0,12"/>
                                        <ComboBox Grid.Row="3" Grid.Column="1" x:Name="ComboNewAction" Margin="0,0,0,12">
                                            <ComboBoxItem Content="Create" IsSelected="True"/>
                                            <ComboBoxItem Content="Update"/>
                                            <ComboBoxItem Content="Replace"/>
                                            <ComboBoxItem Content="Delete"/>
                                        </ComboBox>

                                        <Label Grid.Row="4" Grid.Column="0" Content="Target Users:" Margin="0,0,0,12"/>
                                        <TextBox Grid.Row="4" Grid.Column="1" x:Name="TxtNewTargetUsers" Margin="0,0,0,12" 
                                                 TextWrapping="Wrap" Height="60" AcceptsReturn="True"
                                                 ToolTip="Enter comma-separated sAMAccountNames to test this new mapping"/>
                                    </Grid>

                                    <Button x:Name="BtnSimulateAdd" Content="Simulate &amp; Test for Conflicts" 
                                            Width="250" HorizontalAlignment="Left" Margin="0,8,0,0"/>
                                </StackPanel>
                            </Border>

                            <Border Background="{StaticResource BgCard}" Padding="16" CornerRadius="6">
                                <StackPanel>
                                    <TextBlock Text="Simulation Results" FontSize="14" FontWeight="SemiBold" Margin="0,0,0,12"/>
                                    <TextBox x:Name="TxtSimulationResults" IsReadOnly="True" TextWrapping="Wrap" 
                                             FontFamily="Consolas" FontSize="11" Background="Transparent" 
                                             BorderThickness="0" MinHeight="200" VerticalScrollBarVisibility="Auto"/>
                                </StackPanel>
                            </Border>
                        </StackPanel>
                    </ScrollViewer>
                </Grid>
            </TabItem>

            <!-- TAB 6: Action Log -->
            <TabItem Header="📋 Action Log">
                <Grid Background="{StaticResource BgDeep}">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>

                    <Border Grid.Row="0" Background="{StaticResource BgPanel}" Padding="12" Margin="8,8,8,0">
                        <Grid>
                            <TextBlock Text="Application Activity Log" FontSize="14" FontWeight="SemiBold" VerticalAlignment="Center"/>
                            <Button x:Name="BtnClearLog" Content="Clear Log" Width="100" HorizontalAlignment="Right"/>
                        </Grid>
                    </Border>

                    <DataGrid Grid.Row="1" x:Name="GridActionLog" Margin="8" ItemsSource="{Binding}" AutoGenerateColumns="False">
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="Timestamp" Binding="{Binding Timestamp}" Width="160"/>
                            <DataGridTextColumn Header="Level" Binding="{Binding Level}" Width="80"/>
                            <DataGridTextColumn Header="Message" Binding="{Binding Message}" Width="*"/>
                        </DataGrid.Columns>
                    </DataGrid>
                </Grid>
            </TabItem>

        </TabControl>

        <!-- STATUS BAR -->
        <Border Grid.Row="2" Background="{StaticResource BgPanel}" BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,1,0,0">
            <Grid Margin="12,0">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>

                <TextBlock Grid.Column="0" x:Name="TxtStatusLeft" Text="Ready" VerticalAlignment="Center" 
                           Foreground="{StaticResource Success}" FontSize="12"/>
                
                <TextBlock Grid.Column="2" x:Name="TxtStatusRight" VerticalAlignment="Center" 
                           Foreground="{StaticResource TextSecond}" FontSize="11"/>
            </Grid>
        </Border>
    </Grid>
</Window>
'@
#endregion

#region Action Log Functions
function Write-ActionLog {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = [pscustomobject]@{
        Timestamp = $timestamp
        Level = $Level
        Message = $Message
    }
    
    $script:Window.Dispatcher.Invoke([action]{
        $script:ActionLogEntries.Add($entry)
        
        $color = switch ($Level) {
            'SUCCESS' { 'Green' }
            'WARNING' { 'Yellow' }
            'ERROR' { 'Red' }
            default { 'Gray' }
        }
        
        Write-Host "[$timestamp] $Level : $Message" -ForegroundColor $color
    })
}

function Update-StatusBar {
    param([string]$Message, [string]$Color = 'Success')
    
    $script:Window.Dispatcher.Invoke([action]{
        $statusText = $script:Window.FindName('TxtStatusLeft')
        $statusText.Text = $Message
        
        $brush = switch ($Color) {
            'Success' { $script:Window.Resources['Success'] }
            'Warning' { $script:Window.Resources['Warning'] }
            'Error' { $script:Window.Resources['Danger'] }
            default { $script:Window.Resources['Accent'] }
        }
        
        $statusText.Foreground = $brush
    })
}
#endregion

#region Core GPO Functions
function Load-AvailableDomains {
    try {
        Write-ActionLog "Loading available domains..." "INFO"
        
        $comboDomain = $script:Window.FindName('ComboDomain')
        $comboDomain.Items.Clear()
        
        try {
            $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            $domains = $forest.Domains | Select-Object -ExpandProperty Name | Sort-Object
            
            foreach ($domain in $domains) {
                $comboDomain.Items.Add($domain) | Out-Null
            }
            
            if ($script:CurrentDomain -and $domains -contains $script:CurrentDomain) {
                $comboDomain.SelectedItem = $script:CurrentDomain
            } elseif ($comboDomain.Items.Count -gt 0) {
                $comboDomain.SelectedIndex = 0
            }
            
            Write-ActionLog "Loaded $($comboDomain.Items.Count) domain(s)" "SUCCESS"
        }
        catch {
            $comboDomain.Items.Add($script:CurrentDomain) | Out-Null
            $comboDomain.SelectedIndex = 0
            Write-ActionLog "Using current domain only: $script:CurrentDomain" "WARNING"
        }
    }
    catch {
        Write-ActionLog "Failed to load domains: $($_.Exception.Message)" "ERROR"
        [System.Windows.MessageBox]::Show("Failed to load domains: $($_.Exception.Message)", 
            "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
}

function Load-AvailableGpos {
    param([string]$DomainName)
    
    try {
        Write-ActionLog "Loading GPOs from domain: $DomainName" "INFO"
        Update-StatusBar "Loading GPOs..." "Warning"
        
        $comboGpo = $script:Window.FindName('ComboGpo')
        $comboGpo.Items.Clear()
        
        $gpos = Get-GPO -All -Domain $DomainName -ErrorAction Stop | 
                Where-Object { Test-GpoHasDriveMappings -GpoId $_.Id -Domain $DomainName } |
                Sort-Object DisplayName
        
        foreach ($gpo in $gpos) {
            $item = [pscustomobject]@{
                DisplayName = $gpo.DisplayName
                Id = $gpo.Id
                Domain = $DomainName
            }
            $comboGpo.Items.Add($item) | Out-Null
        }
        
        $comboGpo.DisplayMemberPath = 'DisplayName'
        $comboGpo.IsEnabled = $comboGpo.Items.Count -gt 0
        
        if ($comboGpo.Items.Count -eq 0) {
            Write-ActionLog "No GPOs with drive mappings found in domain $DomainName" "WARNING"
            Update-StatusBar "No GPOs with drive mappings found" "Warning"
        } else {
            Write-ActionLog "Loaded $($comboGpo.Items.Count) GPO(s) with drive mappings" "SUCCESS"
            Update-StatusBar "Ready - $($comboGpo.Items.Count) GPO(s) available" "Success"
        }
    }
    catch {
        Write-ActionLog "Failed to load GPOs: $($_.Exception.Message)" "ERROR"
        Update-StatusBar "Failed to load GPOs" "Error"
        [System.Windows.MessageBox]::Show("Failed to load GPOs from domain $DomainName`n`n$($_.Exception.Message)", 
            "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
}

function Test-GpoHasDriveMappings {
    param([guid]$GpoId, [string]$Domain)
    
    $guid = $GpoId.ToString('B')
    $path = "\\$Domain\SysVol\$Domain\Policies\$guid\User\Preferences\Drives\Drives.xml"
    
    return Test-Path $path
}

function Load-GpoDriveMappings {
    param([object]$GpoItem)
    
    try {
        Write-ActionLog "Loading drive mappings from GPO: $($GpoItem.DisplayName)" "INFO"
        Update-StatusBar "Loading GPO mappings..." "Warning"
        
        $guid = $GpoItem.Id.ToString('B')
        $domain = $GpoItem.Domain
        $xmlPath = "\\$domain\SysVol\$domain\Policies\$guid\User\Preferences\Drives\Drives.xml"
        
        if (-not (Test-Path $xmlPath)) {
            throw "Drives.xml not found at: $xmlPath"
        }
        
        [xml]$drivesXml = Get-Content -Path $xmlPath -Raw -ErrorAction Stop
        $driveNodes = $drivesXml.SelectNodes('//Drive')
        
        $script:LoadedGpo = @{
            DisplayName = $GpoItem.DisplayName
            Id = $GpoItem.Id
            Domain = $domain
            XmlPath = $xmlPath
            Xml = $drivesXml
        }
        
        $script:MappingsData.Clear()
        
        foreach ($driveNode in $driveNodes) {
            $props = $driveNode.SelectSingleNode('Properties')
            if (-not $props) { continue }
            
            $filtersNode = $driveNode.SelectSingleNode('Filters')
            $hasFilters = ($null -ne $filtersNode -and $filtersNode.ChildNodes.Count -gt 0)
            
            $filterSummary = if ($hasFilters) {
                Get-FilterSummary -FiltersNode $filtersNode
            } else {
                "No filters (applies to all)"
            }
            
            $isDisabled = $driveNode.GetAttribute('disabled') -eq '1'
            $state = if ($isDisabled) { "Disabled" } else { "Enabled" }
            
            $mapping = [pscustomobject]@{
                DriveLetter = $props.letter
                Path = $props.path
                Label = $props.label
                Action = $props.action
                State = $state
                HasFilters = if ($hasFilters) { "Yes" } else { "No" }
                FilterSummary = $filterSummary
                XmlNode = $driveNode
            }
            
            $script:MappingsData.Add($mapping)
        }
        
        Update-GpoInfoDisplay
        
        $gridMappings = $script:Window.FindName('GridMappings')
        $gridMappings.ItemsSource = $script:MappingsData
        
        $gridFilterInspector = $script:Window.FindName('GridFilterInspectorDrives')
        $gridFilterInspector.ItemsSource = $script:MappingsData
        
        Load-ComparisonGpoList
        
        Write-ActionLog "Loaded $($script:MappingsData.Count) drive mapping(s) from GPO: $($GpoItem.DisplayName)" "SUCCESS"
        Update-StatusBar "GPO loaded - $($script:MappingsData.Count) mapping(s) found" "Success"
    }
    catch {
        Write-ActionLog "Failed to load GPO: $($_.Exception.Message)" "ERROR"
        Update-StatusBar "Failed to load GPO" "Error"
        [System.Windows.MessageBox]::Show("Failed to load GPO drive mappings:`n`n$($_.Exception.Message)", 
            "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
}

function Get-FilterSummary {
    param([System.Xml.XmlElement]$FiltersNode)
    
    $filters = @()
    
    foreach ($child in $FiltersNode.ChildNodes) {
        if ($child -isnot [System.Xml.XmlElement]) { continue }
        
        $type = $child.LocalName -replace '^Filter', ''
        $name = $child.GetAttribute('name')
        
        if ($name) {
            $filters += "$type`: $name"
        } else {
            $filters += $type
        }
    }
    
    if ($filters.Count -eq 0) { return "Empty filter block" }
    return ($filters -join '; ')
}

function Update-GpoInfoDisplay {
    $txtGpoInfo = $script:Window.FindName('TxtGpoInfo')
    
    if ($null -eq $script:LoadedGpo) {
        $txtGpoInfo.Text = "No GPO loaded."
        return
    }
    
    $info = "GPO: $($script:LoadedGpo.DisplayName)`n" +
            "Domain: $($script:LoadedGpo.Domain)`n" +
            "GUID: $($script:LoadedGpo.Id)`n" +
            "XML Path: $($script:LoadedGpo.XmlPath)"
    
    $txtGpoInfo.Text = $info
}

function Load-ComparisonGpoList {
    if ($null -eq $script:LoadedGpo) { return }
    
    $comboCompare = $script:Window.FindName('ComboCompareGpo')
    $comboCompare.Items.Clear()
    
    try {
        $gpos = Get-GPO -All -Domain $script:LoadedGpo.Domain -ErrorAction Stop | 
                Where-Object { $_.Id -ne $script:LoadedGpo.Id -and (Test-GpoHasDriveMappings -GpoId $_.Id -Domain $script:LoadedGpo.Domain) } |
                Sort-Object DisplayName
        
        foreach ($gpo in $gpos) {
            $item = [pscustomobject]@{
                DisplayName = $gpo.DisplayName
                Id = $gpo.Id
                Domain = $script:LoadedGpo.Domain
            }
            $comboCompare.Items.Add($item) | Out-Null
        }
        
        $comboCompare.DisplayMemberPath = 'DisplayName'
    }
    catch {
        Write-ActionLog "Failed to load comparison GPO list: $($_.Exception.Message)" "WARNING"
    }
}
#endregion

#region Validation Engine (Integrated from Test-GpoDriveMapTargeting.ps1)
function Invoke-UserValidation {
    param(
        [string]$Mode,
        [string]$Input
    )
    
    if ($null -eq $script:LoadedGpo) {
        [System.Windows.MessageBox]::Show("No GPO loaded. Please load a GPO first.", 
            "Validation Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }
    
    if ([string]::IsNullOrWhiteSpace($Input)) {
        [System.Windows.MessageBox]::Show("Please enter validation input.", 
            "Validation Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }
    
    try {
        Write-ActionLog "Starting user validation (Mode: $Mode)" "INFO"
        Update-StatusBar "Running validation..." "Warning"
        
        $scriptPath = Join-Path $PSScriptRoot 'Test-GpoDriveMapTargeting.ps1'
        
        if (-not (Test-Path $scriptPath)) {
            throw "Validation script not found: $scriptPath"
        }
        
        $params = @{
            DrivesXmlPath = $script:LoadedGpo.XmlPath
            Domain = $script:LoadedGpo.Domain
            ReturnObject = $true
        }
        
        switch -Regex ($Mode) {
            'Single User' {
                $params['TargetUsers'] = @($Input.Trim())
            }
            'All Users in OU' {
                $params['TargetOU'] = $Input.Trim()
            }
            'User List' {
                $users = $Input -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                $params['TargetUsers'] = $users
            }
        }
        
        $result = & $scriptPath @params
        
        if ($null -eq $result) {
            throw "Validation script returned no results"
        }
        
        $script:ValidationResults = $result.Results
        $script:ConflictData = @()
        
        $gridResults = $script:Window.FindName('GridValidationResults')
        $gridResults.ItemsSource = $script:ValidationResults
        
        $txtTrace = $script:Window.FindName('TxtFilterTrace')
        $traceText = ($script:ValidationResults | ForEach-Object { $_.Trace }) -join "`n`n========================================`n`n"
        $txtTrace.Text = $traceText
        
        $conflicts = $result.Conflicts
        if ($conflicts.Count -gt 0) {
            foreach ($conflict in $conflicts) {
                $parts = $conflict.Name -split ', '
                $user = $parts[0]
                $letter = $parts[1]
                $paths = ($conflict.Group | ForEach-Object { $_.Path }) -join ' | '
                
                $script:ConflictData += [pscustomobject]@{
                    User = $user
                    DriveLetter = $letter
                    Paths = $paths
                }
            }
            
            $txtConflictSummary = $script:Window.FindName('TxtConflictSummary')
            $txtConflictSummary.Text = "⚠ $($conflicts.Count) conflict(s) detected!"
            $txtConflictSummary.Foreground = $script:Window.Resources['Danger']
            
            Write-ActionLog "Validation complete - $($conflicts.Count) conflict(s) detected" "WARNING"
        } else {
            $txtConflictSummary = $script:Window.FindName('TxtConflictSummary')
            $txtConflictSummary.Text = "✓ No conflicts detected."
            $txtConflictSummary.Foreground = $script:Window.Resources['Success']
            
            Write-ActionLog "Validation complete - No conflicts detected" "SUCCESS"
        }
        
        $gridConflicts = $script:Window.FindName('GridConflicts')
        $gridConflicts.ItemsSource = $script:ConflictData
        
        $panelWarnings = $script:Window.FindName('PanelWarnings')
        $panelWarnings.Children.Clear()
        
        if ($result.Warnings.Count -gt 0) {
            foreach ($warning in $result.Warnings) {
                $tb = New-Object System.Windows.Controls.TextBlock
                $tb.Text = "⚠ $warning"
                $tb.Foreground = $script:Window.Resources['Warning']
                $tb.TextWrapping = [System.Windows.TextWrapping]::Wrap
                $tb.Margin = New-Object System.Windows.Thickness(0, 0, 0, 8)
                $panelWarnings.Children.Add($tb) | Out-Null
            }
        } else {
            $tb = New-Object System.Windows.Controls.TextBlock
            $tb.Text = "✓ No warnings."
            $tb.Foreground = $script:Window.Resources['Success']
            $panelWarnings.Children.Add($tb) | Out-Null
        }
        
        $validationTabs = $script:Window.FindName('ValidationTabs')
        $validationTabs.SelectedIndex = 0
        
        Update-StatusBar "Validation complete - $($script:ValidationResults.Count) result(s)" "Success"
    }
    catch {
        Write-ActionLog "Validation failed: $($_.Exception.Message)" "ERROR"
        Update-StatusBar "Validation failed" "Error"
        [System.Windows.MessageBox]::Show("Validation failed:`n`n$($_.Exception.Message)", 
            "Validation Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
}
#endregion

#region GPO Comparison
function Invoke-GpoComparison {
    param([object]$CompareGpoItem)
    
    if ($null -eq $script:LoadedGpo) {
        [System.Windows.MessageBox]::Show("No GPO loaded. Please load a GPO first.", 
            "Comparison Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }
    
    if ($null -eq $CompareGpoItem) {
        [System.Windows.MessageBox]::Show("Please select a GPO to compare with.", 
            "Comparison Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }
    
    try {
        Write-ActionLog "Comparing GPOs: $($script:LoadedGpo.DisplayName) vs $($CompareGpoItem.DisplayName)" "INFO"
        Update-StatusBar "Comparing GPOs..." "Warning"
        
        $guid = $CompareGpoItem.Id.ToString('B')
        $domain = $CompareGpoItem.Domain
        $xmlPath = "\\$domain\SysVol\$domain\Policies\$guid\User\Preferences\Drives\Drives.xml"
        
        if (-not (Test-Path $xmlPath)) {
            throw "Drives.xml not found for comparison GPO at: $xmlPath"
        }
        
        [xml]$compareXml = Get-Content -Path $xmlPath -Raw -ErrorAction Stop
        $compareNodes = $compareXml.SelectNodes('//Drive')
        
        $compareMappings = @{}
        foreach ($node in $compareNodes) {
            $props = $node.SelectSingleNode('Properties')
            if ($props) {
                $compareMappings[$props.letter] = $props.path
            }
        }
        
        $comparisonData = New-Object System.Collections.ObjectModel.ObservableCollection[object]
        
        $allLetters = @($script:MappingsData.DriveLetter) + @($compareMappings.Keys) | Select-Object -Unique | Sort-Object
        
        foreach ($letter in $allLetters) {
            $currentPath = ($script:MappingsData | Where-Object { $_.DriveLetter -eq $letter }).Path
            $comparePath = $compareMappings[$letter]
            
            $status = if ($currentPath -and $comparePath) {
                if ($currentPath -eq $comparePath) { "Same" } else { "Different" }
            } elseif ($currentPath) {
                "Only in Current"
            } else {
                "Only in Compare"
            }
            
            $comparisonData.Add([pscustomobject]@{
                DriveLetter = $letter
                CurrentPath = $currentPath
                ComparePath = $comparePath
                Status = $status
            })
        }
        
        $gridComparison = $script:Window.FindName('GridComparison')
        $gridComparison.ItemsSource = $comparisonData
        
        Write-ActionLog "Comparison complete - $($comparisonData.Count) drive letter(s) analyzed" "SUCCESS"
        Update-StatusBar "Comparison complete" "Success"
    }
    catch {
        Write-ActionLog "Comparison failed: $($_.Exception.Message)" "ERROR"
        Update-StatusBar "Comparison failed" "Error"
        [System.Windows.MessageBox]::Show("GPO comparison failed:`n`n$($_.Exception.Message)", 
            "Comparison Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
}
#endregion

#region Add Mapping Simulator
function Invoke-AddMappingSimulation {
    param(
        [string]$DriveLetter,
        [string]$Path,
        [string]$Label,
        [string]$Action,
        [string]$TargetUsers
    )
    
    if ($null -eq $script:LoadedGpo) {
        [System.Windows.MessageBox]::Show("No GPO loaded. Please load a GPO first.", 
            "Simulation Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }
    
    if ([string]::IsNullOrWhiteSpace($DriveLetter) -or [string]::IsNullOrWhiteSpace($Path)) {
        [System.Windows.MessageBox]::Show("Drive Letter and Path are required.", 
            "Simulation Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }
    
    try {
        Write-ActionLog "Simulating new mapping: $DriveLetter -> $Path" "INFO"
        Update-StatusBar "Running simulation..." "Warning"
        
        $results = New-Object System.Text.StringBuilder
        $results.AppendLine("=== ADD MAPPING SIMULATION ===") | Out-Null
        $results.AppendLine("Drive Letter: $DriveLetter") | Out-Null
        $results.AppendLine("Path: $Path") | Out-Null
        $results.AppendLine("Label: $Label") | Out-Null
        $results.AppendLine("Action: $Action") | Out-Null
        $results.AppendLine("") | Out-Null
        
        $existingMapping = $script:MappingsData | Where-Object { $_.DriveLetter -eq $DriveLetter }
        
        if ($existingMapping) {
            $results.AppendLine("⚠ WARNING: Drive letter $DriveLetter already exists in this GPO:") | Out-Null
            $results.AppendLine("   Current Path: $($existingMapping.Path)") | Out-Null
            $results.AppendLine("   Current Label: $($existingMapping.Label)") | Out-Null
            $results.AppendLine("   Current State: $($existingMapping.State)") | Out-Null
            $results.AppendLine("") | Out-Null
        }
        
        if (-not [string]::IsNullOrWhiteSpace($TargetUsers)) {
            $results.AppendLine("=== CONFLICT TESTING ===") | Out-Null
            
            $users = $TargetUsers -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            $results.AppendLine("Testing against users: $($users -join ', ')") | Out-Null
            $results.AppendLine("") | Out-Null
            
            $scriptPath = Join-Path $PSScriptRoot 'Test-GpoDriveMapTargeting.ps1'
            
            if (Test-Path $scriptPath) {
                $params = @{
                    DrivesXmlPath = $script:LoadedGpo.XmlPath
                    Domain = $script:LoadedGpo.Domain
                    TargetUsers = $users
                    ReturnObject = $true
                }
                
                $validationResult = & $scriptPath @params
                
                $conflictsForLetter = $validationResult.Results | 
                    Where-Object { $_.DriveLetter -eq $DriveLetter -and $_.Applies -and -not $_.IsDisabled }
                
                if ($conflictsForLetter.Count -gt 0) {
                    $results.AppendLine("⚠ POTENTIAL CONFLICTS DETECTED:") | Out-Null
                    $results.AppendLine("The following users already receive drive $DriveLetter from existing mappings:") | Out-Null
                    
                    foreach ($conflict in $conflictsForLetter) {
                        $results.AppendLine("   - $($conflict.Subject): $($conflict.Path)") | Out-Null
                    }
                    
                    $results.AppendLine("") | Out-Null
                    $results.AppendLine("Adding this new mapping will create a drive letter conflict!") | Out-Null
                } else {
                    $results.AppendLine("✓ No conflicts detected for the specified users.") | Out-Null
                    $results.AppendLine("The new mapping can be safely added.") | Out-Null
                }
            } else {
                $results.AppendLine("⚠ Validation script not found - cannot test for conflicts.") | Out-Null
            }
        } else {
            $results.AppendLine("ℹ No target users specified - skipping conflict testing.") | Out-Null
            $results.AppendLine("Enter user names to test for conflicts.") | Out-Null
        }
        
        $txtResults = $script:Window.FindName('TxtSimulationResults')
        $txtResults.Text = $results.ToString()
        
        Write-ActionLog "Simulation complete" "SUCCESS"
        Update-StatusBar "Simulation complete" "Success"
    }
    catch {
        Write-ActionLog "Simulation failed: $($_.Exception.Message)" "ERROR"
        Update-StatusBar "Simulation failed" "Error"
        [System.Windows.MessageBox]::Show("Simulation failed:`n`n$($_.Exception.Message)", 
            "Simulation Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
}
#endregion

#region Event Handlers
function Initialize-EventHandlers {
    $comboDomain = $script:Window.FindName('ComboDomain')
    $comboDomain.add_SelectionChanged({
        if ($comboDomain.SelectedItem) {
            $script:CurrentDomain = $comboDomain.SelectedItem
            Load-AvailableGpos -DomainName $script:CurrentDomain
        }
    })
    
    $btnLoadGpo = $script:Window.FindName('BtnLoadGpo')
    $btnLoadGpo.add_Click({
        $comboGpo = $script:Window.FindName('ComboGpo')
        if ($comboGpo.SelectedItem) {
            Load-GpoDriveMappings -GpoItem $comboGpo.SelectedItem
        } else {
            [System.Windows.MessageBox]::Show("Please select a GPO to load.", 
                "No Selection", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
    })
    
    $btnRefresh = $script:Window.FindName('BtnRefresh')
    $btnRefresh.add_Click({
        Load-AvailableDomains
        if ($script:CurrentDomain) {
            Load-AvailableGpos -DomainName $script:CurrentDomain
        }
    })
    
    $btnRunValidation = $script:Window.FindName('BtnRunValidation')
    $btnRunValidation.add_Click({
        $comboMode = $script:Window.FindName('ComboValidationMode')
        $txtInput = $script:Window.FindName('TxtValidationInput')
        
        $mode = $comboMode.SelectedItem.Content
        $input = $txtInput.Text
        
        Invoke-UserValidation -Mode $mode -Input $input
    })
    
    $btnCompare = $script:Window.FindName('BtnCompare')
    $btnCompare.add_Click({
        $comboCompare = $script:Window.FindName('ComboCompareGpo')
        if ($comboCompare.SelectedItem) {
            Invoke-GpoComparison -CompareGpoItem $comboCompare.SelectedItem
        }
    })
    
    $btnSimulateAdd = $script:Window.FindName('BtnSimulateAdd')
    $btnSimulateAdd.add_Click({
        $letter = $script:Window.FindName('TxtNewDriveLetter').Text
        $path = $script:Window.FindName('TxtNewPath').Text
        $label = $script:Window.FindName('TxtNewLabel').Text
        $action = $script:Window.FindName('ComboNewAction').SelectedItem.Content
        $users = $script:Window.FindName('TxtNewTargetUsers').Text
        
        Invoke-AddMappingSimulation -DriveLetter $letter -Path $path -Label $label -Action $action -TargetUsers $users
    })
    
    $btnClearLog = $script:Window.FindName('BtnClearLog')
    $btnClearLog.add_Click({
        $script:ActionLogEntries.Clear()
        Write-ActionLog "Log cleared" "INFO"
    })
    
    $gridFilterInspector = $script:Window.FindName('GridFilterInspectorDrives')
    $gridFilterInspector.add_SelectionChanged({
        if ($gridFilterInspector.SelectedItem) {
            $mapping = $gridFilterInspector.SelectedItem
            $filtersNode = $mapping.XmlNode.SelectSingleNode('Filters')
            
            $txtDetail = $script:Window.FindName('TxtFilterInspectorDetail')
            
            if ($null -eq $filtersNode -or $filtersNode.ChildNodes.Count -eq 0) {
                $txtDetail.Text = "No Item-Level Targeting filters configured for this drive mapping.`n`n" +
                                  "This mapping applies to ALL users."
            } else {
                $sb = New-Object System.Text.StringBuilder
                $sb.AppendLine("Drive: $($mapping.DriveLetter)") | Out-Null
                $sb.AppendLine("Path: $($mapping.Path)") | Out-Null
                $sb.AppendLine("") | Out-Null
                $sb.AppendLine("=== FILTER TREE ===") | Out-Null
                $sb.AppendLine("") | Out-Null
                
                Format-FilterTreeRecursive -Node $filtersNode -StringBuilder $sb -Depth 0
                
                $txtDetail.Text = $sb.ToString()
            }
        }
    })
}

function Format-FilterTreeRecursive {
    param(
        [System.Xml.XmlElement]$Node,
        [System.Text.StringBuilder]$StringBuilder,
        [int]$Depth
    )
    
    $indent = '  ' * $Depth
    
    foreach ($child in $Node.ChildNodes) {
        if ($child -isnot [System.Xml.XmlElement]) { continue }
        
        $type = $child.LocalName -replace '^Filter', ''
        $name = $child.GetAttribute('name')
        $bool = $child.GetAttribute('bool')
        $not = $child.GetAttribute('not')
        
        $line = "$indent[$type]"
        if ($name) { $line += " '$name'" }
        if ($bool) { $line += " (bool=$bool)" }
        if ($not -eq '1') { $line += " [NOT]" }
        
        $StringBuilder.AppendLine($line) | Out-Null
        
        if ($child.LocalName -eq 'FilterCollection') {
            Format-FilterTreeRecursive -Node $child -StringBuilder $StringBuilder -Depth ($Depth + 1)
        }
    }
}
#endregion

#region Main Window Initialization
try {
    Write-Host "Initializing GPO Drive Mapping Validator & Manager..." -ForegroundColor Cyan
    
    $reader = New-Object System.Xml.XmlNodeReader([xml]$xaml)
    $script:Window = [Windows.Markup.XamlReader]::Load($reader)
    
    if ($null -eq $script:Window) {
        throw "Failed to create window from XAML"
    }
    
    $gridActionLog = $script:Window.FindName('GridActionLog')
    $gridActionLog.ItemsSource = $script:ActionLogEntries
    
    Initialize-EventHandlers
    
    $script:Window.add_Loaded({
        Write-ActionLog "Application started" "SUCCESS"
        Update-StatusBar "Ready" "Success"
        
        $txtStatusRight = $script:Window.FindName('TxtStatusRight')
        
        $timer = New-Object System.Windows.Threading.DispatcherTimer
        $timer.Interval = [TimeSpan]::FromSeconds(1)
        $timer.Add_Tick({
            $txtStatusRight.Text = Get-Date -Format 'HH:mm:ss'
        })
        $timer.Start()
        
        Load-AvailableDomains
        if ($script:CurrentDomain) {
            Load-AvailableGpos -DomainName $script:CurrentDomain
        }
    })
    
    $script:Window.add_Closing({
        Write-ActionLog "Application closing" "INFO"
    })
    
    Write-Host "Launching UI..." -ForegroundColor Cyan
    [void]$script:Window.ShowDialog()
}
catch {
    $errorMsg = "Fatal error during initialization: $($_.Exception.Message)`n`nStack Trace:`n$($_.ScriptStackTrace)"
    Write-Host $errorMsg -ForegroundColor Red
    
    [System.Windows.Forms.MessageBox]::Show(
        $errorMsg,
        "Fatal Error",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
    
    exit 1
}
#endregion
