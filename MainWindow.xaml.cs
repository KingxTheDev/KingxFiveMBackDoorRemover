using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace BackdoorScanner;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<ScanResult> _results = new();
    private string? _scanRoot;

    public MainWindow()
    {
        InitializeComponent();
        ResultsGrid.ItemsSource = _results;
    }

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFolderDialog { Title = "Select FiveM resources folder" };
        if (dialog.ShowDialog(this) == true)
        {
            PathBox.Text = dialog.FolderName;
        }
    }

    private void OpenFolder_Click(object sender, RoutedEventArgs e)
    {
        var path = PathBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path))
        {
            ShowAlert("Path does not exist.");
            return;
        }

        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(path) { UseShellExecute = true });
    }

    private void Row_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (sender is DataGridRow row && !row.IsSelected)
        {
            ResultsGrid.SelectedItems.Clear();
            row.IsSelected = true;
        }
    }

    private void CtxOpenFile_Click(object sender, RoutedEventArgs e)
    {
        foreach (var result in ResultsGrid.SelectedItems.Cast<ScanResult>())
        {
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(result.FullPath) { UseShellExecute = true });
            }
            catch (System.ComponentModel.Win32Exception)
            {
                ShowAlert($"Couldn't open {result.RelativePath} - no default app is associated with .js files.");
            }
        }
    }

    private void CtxOpenFileLocation_Click(object sender, RoutedEventArgs e)
    {
        foreach (var result in ResultsGrid.SelectedItems.Cast<ScanResult>())
        {
            System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{result.FullPath}\"");
        }
    }

    private void ShowAlert(string? message)
    {
        AlertText.Text = message ?? "";
        AlertText.Visibility = string.IsNullOrEmpty(message) ? Visibility.Collapsed : Visibility.Visible;
    }

    private async void Scan_Click(object sender, RoutedEventArgs e)
    {
        var root = PathBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
        {
            ShowAlert("Path does not exist.");
            return;
        }

        ShowAlert(null);
        _scanRoot = root;
        _results.Clear();
        ResultsSub.Text = "Scanning...";

        var progress = new Progress<int>(count => ResultsSub.Text = $"Scanning... {count} files checked");

        List<ScanResult> results;
        try
        {
            results = await Task.Run(() => Scanner.Scan(root, progress).ToList());
        }
        catch (Exception ex)
        {
            ShowAlert($"Scan failed: {ex.Message}");
            ResultsSub.Text = "Run a scan to see suspicious files";
            return;
        }

        foreach (var result in results) _results.Add(result);
        ResultsSub.Text = results.Count == 0
            ? "No suspicious files found"
            : $"{results.Count} suspicious file(s) found";
    }

    private async void QuarantineSelected_Click(object sender, RoutedEventArgs e)
        => await QuarantineAsync(ResultsGrid.SelectedItems.Cast<ScanResult>().ToList());

    private async void CtxQuarantine_Click(object sender, RoutedEventArgs e)
        => await QuarantineAsync(ResultsGrid.SelectedItems.Cast<ScanResult>().ToList());

    private async void DeleteSelected_Click(object sender, RoutedEventArgs e)
        => await DeleteWithConfirmationAsync(ResultsGrid.SelectedItems.Cast<ScanResult>().ToList());

    private async void CtxDelete_Click(object sender, RoutedEventArgs e)
        => await DeleteWithConfirmationAsync(ResultsGrid.SelectedItems.Cast<ScanResult>().ToList());

    private async Task QuarantineAsync(List<ScanResult> selected)
    {
        if (_scanRoot is null || selected.Count == 0)
        {
            ShowAlert("Select at least one file first.");
            return;
        }

        var scanRoot = _scanRoot;
        var quarantineRoot = Path.Combine(scanRoot, "_quarantine");

        var moved = await Task.Run(() =>
        {
            var movedResults = new List<ScanResult>();
            foreach (var result in selected)
            {
                try
                {
                    Scanner.Quarantine(result, scanRoot, quarantineRoot);
                    movedResults.Add(result);
                }
                catch (IOException)
                {
                    // skip files that failed to move, leave them listed for retry
                }
            }
            return movedResults;
        });

        foreach (var result in moved) _results.Remove(result);
        ResultsSub.Text = $"{_results.Count} suspicious file(s) found";
        if (moved.Count < selected.Count) ShowAlert("Some files could not be moved (in use?).");
    }

    private async Task DeleteWithConfirmationAsync(List<ScanResult> selected)
    {
        if (selected.Count == 0)
        {
            ShowAlert("Select at least one file first.");
            return;
        }

        var label = selected.Count == 1 ? selected[0].RelativePath : $"{selected.Count} selected files";
        var confirm = MessageBox.Show(
            $"Delete {label} permanently?\n\nThis can't be undone. Quarantine instead if you want to keep a copy.",
            "Delete Permanently",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;

        var deleted = await Task.Run(() =>
        {
            var deletedResults = new List<ScanResult>();
            foreach (var result in selected)
            {
                try
                {
                    var attrs = File.GetAttributes(result.FullPath);
                    if (attrs.HasFlag(FileAttributes.Hidden))
                    {
                        File.SetAttributes(result.FullPath, attrs & ~FileAttributes.Hidden);
                    }

                    File.Delete(result.FullPath);
                    deletedResults.Add(result);
                }
                catch (IOException)
                {
                    // skip files that failed to delete, leave them listed for retry
                }
            }
            return deletedResults;
        });

        foreach (var result in deleted) _results.Remove(result);
        ResultsSub.Text = $"{_results.Count} suspicious file(s) found";
        if (deleted.Count < selected.Count) ShowAlert("Some files could not be deleted (in use?).");
    }

    private async void OpenQuarantine_Click(object sender, RoutedEventArgs e)
    {
        var root = _scanRoot ?? PathBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
        {
            LogView.Text = "";
            return;
        }

        var quarantineRoot = Path.Combine(root, "_quarantine");
        Directory.CreateDirectory(quarantineRoot);
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(quarantineRoot) { UseShellExecute = true });

        var logPath = Path.Combine(quarantineRoot, "quarantine-log.txt");
        LogView.Text = await Task.Run(() => File.Exists(logPath) ? File.ReadAllText(logPath) : "");
    }
}
