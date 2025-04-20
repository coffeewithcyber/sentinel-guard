document.addEventListener('DOMContentLoaded', function() {
    // Form validation
    const settingsForm = document.getElementById('settings-form');
    if (settingsForm) {
        settingsForm.addEventListener('submit', function(event) {
            if (!validateSettingsForm()) {
                event.preventDefault();
            }
        });
    }
    
    // Threshold sliders
    const criticalThreshold = document.getElementById('alert-threshold-critical');
    const highThreshold = document.getElementById('alert-threshold-high');
    const mediumThreshold = document.getElementById('alert-threshold-medium');
    const lowThreshold = document.getElementById('alert-threshold-low');
    
    const criticalValue = document.getElementById('critical-value');
    const highValue = document.getElementById('high-value');
    const mediumValue = document.getElementById('medium-value');
    const lowValue = document.getElementById('low-value');
    
    // Update the displayed value when sliders change
    if (criticalThreshold) {
        criticalThreshold.addEventListener('input', function() {
            criticalValue.textContent = this.value;
        });
    }
    
    if (highThreshold) {
        highThreshold.addEventListener('input', function() {
            highValue.textContent = this.value;
        });
    }
    
    if (mediumThreshold) {
        mediumThreshold.addEventListener('input', function() {
            mediumValue.textContent = this.value;
        });
    }
    
    if (lowThreshold) {
        lowThreshold.addEventListener('input', function() {
            lowValue.textContent = this.value;
        });
    }
    
    // Toggle email notification settings
    const emailNotifications = document.getElementById('email-notifications');
    const emailSettings = document.getElementById('email-settings');
    
    if (emailNotifications && emailSettings) {
        emailNotifications.addEventListener('change', function() {
            if (this.checked) {
                emailSettings.classList.remove('d-none');
            } else {
                emailSettings.classList.add('d-none');
            }
        });
        
        // Initial state
        if (!emailNotifications.checked) {
            emailSettings.classList.add('d-none');
        }
    }
    
    // Test SMTP connection
    const testSmtpBtn = document.getElementById('test-smtp');
    if (testSmtpBtn) {
        testSmtpBtn.addEventListener('click', function() {
            const server = document.getElementById('smtp-server').value;
            const port = document.getElementById('smtp-port').value;
            const username = document.getElementById('smtp-username').value;
            const password = document.getElementById('smtp-password').value;
            
            if (!server || !port) {
                showAlert('Please enter SMTP server and port', 'danger');
                return;
            }
            
            // Disable button and show loading
            testSmtpBtn.disabled = true;
            testSmtpBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Testing...';
            
            // Send test request
            fetch('/api/test_smtp', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    server: server,
                    port: port,
                    username: username,
                    password: password
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showAlert('SMTP connection successful!', 'success');
                } else {
                    showAlert('SMTP connection failed: ' + data.error, 'danger');
                }
            })
            .catch(error => {
                showAlert('Error testing SMTP connection', 'danger');
                console.error('Error:', error);
            })
            .finally(() => {
                // Re-enable button
                testSmtpBtn.disabled = false;
                testSmtpBtn.innerHTML = 'Test Connection';
            });
        });
    }
    
    // Function to validate the settings form
    function validateSettingsForm() {
        const emailNotificationsEnabled = document.getElementById('email-notifications').checked;
        
        if (emailNotificationsEnabled) {
            const emailRecipients = document.getElementById('email-recipients').value;
            const smtpServer = document.getElementById('smtp-server').value;
            const smtpPort = document.getElementById('smtp-port').value;
            
            if (!emailRecipients) {
                showAlert('Please enter at least one email recipient', 'danger');
                return false;
            }
            
            if (!smtpServer) {
                showAlert('Please enter an SMTP server', 'danger');
                return false;
            }
            
            if (!smtpPort) {
                showAlert('Please enter an SMTP port', 'danger');
                return false;
            }
            
            // Validate email format
            const emails = emailRecipients.split(',').map(email => email.trim());
            for (let email of emails) {
                if (!isValidEmail(email)) {
                    showAlert(`Invalid email format: ${email}`, 'danger');
                    return false;
                }
            }
        }
        
        // Validate threshold values (they should be in descending order)
        const criticalValue = parseInt(document.getElementById('alert-threshold-critical').value);
        const highValue = parseInt(document.getElementById('alert-threshold-high').value);
        const mediumValue = parseInt(document.getElementById('alert-threshold-medium').value);
        const lowValue = parseInt(document.getElementById('alert-threshold-low').value);
        
        if (criticalValue <= highValue) {
            showAlert('Critical threshold must be higher than High threshold', 'danger');
            return false;
        }
        
        if (highValue <= mediumValue) {
            showAlert('High threshold must be higher than Medium threshold', 'danger');
            return false;
        }
        
        if (mediumValue <= lowValue) {
            showAlert('Medium threshold must be higher than Low threshold', 'danger');
            return false;
        }
        
        return true;
    }
    
    // Helper to check if email is valid
    function isValidEmail(email) {
        const re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
        return re.test(String(email).toLowerCase());
    }
    
    // Helper to show alert messages
    function showAlert(message, type) {
        const alertsContainer = document.getElementById('settings-alerts');
        
        if (alertsContainer) {
            const alert = document.createElement('div');
            alert.className = `alert alert-${type} alert-dismissible fade show`;
            alert.innerHTML = `
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            `;
            
            alertsContainer.appendChild(alert);
            
            // Auto-dismiss after 5 seconds
            setTimeout(() => {
                alert.classList.remove('show');
                setTimeout(() => {
                    alertsContainer.removeChild(alert);
                }, 150);
            }, 5000);
        }
    }
});
