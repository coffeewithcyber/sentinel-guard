document.addEventListener('DOMContentLoaded', function() {
    // Initialize date pickers
    flatpickr("#start-date", {
        enableTime: false,
        dateFormat: "Y-m-d",
        maxDate: "today",
        defaultDate: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) // 7 days ago
    });
    
    flatpickr("#end-date", {
        enableTime: false,
        dateFormat: "Y-m-d",
        maxDate: "today",
        defaultDate: "today"
    });
    
    // Initialize DataTable for reports list
    $('#reports-table').DataTable({
        order: [[3, 'desc']], // Order by created date descending
        responsive: true,
        language: {
            search: "_INPUT_",
            searchPlaceholder: "Search reports"
        }
    });
    
    // Form validation
    const reportForm = document.getElementById('report-form');
    if (reportForm) {
        reportForm.addEventListener('submit', function(event) {
            if (!validateReportForm()) {
                event.preventDefault();
            }
        });
    }
    
    // Function to validate the report form
    function validateReportForm() {
        const startDate = document.getElementById('start-date').value;
        const endDate = document.getElementById('end-date').value;
        const reportType = document.getElementById('report-type').value;
        const formatType = document.getElementById('format-type').value;
        
        if (!startDate) {
            showValidationError('Please select a start date');
            return false;
        }
        
        if (!endDate) {
            showValidationError('Please select an end date');
            return false;
        }
        
        // Check that start date is before end date
        const start = new Date(startDate);
        const end = new Date(endDate);
        
        if (start > end) {
            showValidationError('Start date must be before end date');
            return false;
        }
        
        // Check that the date range is not too large
        const diffTime = Math.abs(end - start);
        const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
        
        if (diffDays > 90) {
            showValidationError('Date range cannot exceed 90 days');
            return false;
        }
        
        if (!reportType) {
            showValidationError('Please select a report type');
            return false;
        }
        
        if (!formatType) {
            showValidationError('Please select a format type');
            return false;
        }
        
        return true;
    }
    
    // Function to show validation error
    function showValidationError(message) {
        const errorAlert = document.getElementById('form-error');
        errorAlert.textContent = message;
        errorAlert.classList.remove('d-none');
        
        // Automatically hide the error after 5 seconds
        setTimeout(() => {
            errorAlert.classList.add('d-none');
        }, 5000);
    }
    
    // Handle file format selection based on report type
    const reportTypeSelect = document.getElementById('report-type');
    const formatTypeSelect = document.getElementById('format-type');
    
    if (reportTypeSelect && formatTypeSelect) {
        reportTypeSelect.addEventListener('change', function() {
            // Reset the format select
            formatTypeSelect.innerHTML = '';
            
            // Add PDF option for all report types
            const pdfOption = document.createElement('option');
            pdfOption.value = 'pdf';
            pdfOption.textContent = 'PDF';
            formatTypeSelect.appendChild(pdfOption);
            
            // Add CSV and JSON options for alerts and traffic reports
            if (this.value === 'alerts' || this.value === 'traffic') {
                const csvOption = document.createElement('option');
                csvOption.value = 'csv';
                csvOption.textContent = 'CSV';
                formatTypeSelect.appendChild(csvOption);
                
                const jsonOption = document.createElement('option');
                jsonOption.value = 'json';
                jsonOption.textContent = 'JSON';
                formatTypeSelect.appendChild(jsonOption);
            }
            
            // Add TXT option for all report types
            const txtOption = document.createElement('option');
            txtOption.value = 'txt';
            txtOption.textContent = 'Text';
            formatTypeSelect.appendChild(txtOption);
        });
        
        // Trigger the change event to initialize the format select
        reportTypeSelect.dispatchEvent(new Event('change'));
    }
});
