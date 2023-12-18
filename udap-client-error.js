class udapClientError extends Error {
    constructor(error) {
        if (error instanceof Error) {
            if (error.isAxiosError) {
                if (error.response.data.error_description) {
                    super(error.response.data.error_description)
                }
                else if (error.response.data.Message)
                {
                    super(error.response.data.Message + ' - ' + error.message)
                } else if (error.response.data.message)
                {
                    super(error.response.data.message + ' - ' + error.message)
                } else if (typeof error.response.data == 'string') {
                    super(error.response.data + ' - ' + error.message)
                }
                else {
                    super(error.message)
                }
                if (error.response.data.error) {
                    this.code = error.response.data.error
                }
                else {
                    this.code = error.code
                }
            }
            else {
                super(error.message)
                this.code = error.code
            }
        } else {
            super(error)
        }

        // assign the error class name in your custom error (as a shortcut)
        this.name = this.constructor.name

        // capturing the stack trace keeps the reference to your error class
        Error.captureStackTrace(this, this.constructor);

    }
}

module.exports = udapClientError  