//
//  MyButtonStyle.swift
//  chachaCryptor
//
//  Created by KarUpas on 2025/07/17.
//

import SwiftUI

struct MyButtonStyle: ButtonStyle {
    var color: Color
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .padding(.horizontal, 20).padding(.vertical, 12)
            .frame(maxWidth: .infinity)
            .background(color).foregroundColor(.white)
            .clipShape(Capsule())
            .scaleEffect(configuration.isPressed ? 0.97 : 1.0)
            .animation(.easeOut(duration: 0.2), value: configuration.isPressed)
    }
}




