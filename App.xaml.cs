using System.Windows;
using System.Windows.Threading;

namespace BackdoorScanner;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnDispatcherUnhandledException;
    }

    private static void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show(
            $"An unexpected error occurred and the app needs to close:\n\n{e.Exception.Message}",
            "Backdoor Scanner - Error",
            MessageBoxButton.OK,
            MessageBoxImage.Error);
        e.Handled = true;
        Current.Shutdown();
    }
}
