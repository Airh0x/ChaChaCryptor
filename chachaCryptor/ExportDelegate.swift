//
//  ExportDelegate.swift
//  chachaCryptor
//
//  Created by KarUpas on 2025/07/17.
//

import UIKit

class ExportDelegate: NSObject, UIDocumentPickerDelegate {
    let onSuccess: (URL) -> Void
    let onFailure: (Error) -> Void

    init(onSuccess: @escaping (URL) -> Void, onFailure: @escaping (Error) -> Void) {
        self.onSuccess = onSuccess
        self.onFailure = onFailure
    }

    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        guard let url = urls.first else {
            onFailure(CryptoError.streamError("Export was cancelled or failed."))
            return
        }
        onSuccess(url)
    }
    
    func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
        onFailure(CryptoError.streamError("Export was cancelled."))
    }
}




